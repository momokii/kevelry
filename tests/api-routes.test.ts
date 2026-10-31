// New-test justification (plan todo 14): the versioned read-only API is the
// first network-surface reader over the accepted SQLite snapshots, so tests
// must prove against the real services (not fixtures of the shape) that every
// v1 GET route serves the same code the site reads: default-priority listing
// with stable cursors, one-record lookup, FTS search with excerpts and
// official links, the four named priority views with ordering rules and
// rising deltas, the radar feed with before/after evidence, retained
// checkpoint listing, snapshot replay that reproduces retained results or
// fails with the named REPLAY_UNAVAILABLE reason, overview buckets with an
// explicit unknown-date count, and status/health with per-source dates plus
// the policy version in every response. Unknown EPSS stays explicit null
// (never 0) beside a real known zero; oversized limits and injection-shaped
// queries are rejected with rate-limit headers present. Fixture IDs are
// invented CVE-2099 values; nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { writeCheckpoint } from "../src/lib/radar";
import { loadEpssHistory, resetDbOverride, setDbOverride } from "../app/api/v1/_lib/shared";
import { GET as getCves } from "../app/api/v1/cves/route";
import { GET as getCveById } from "../app/api/v1/cves/[cveId]/route";
import { GET as getSearch } from "../app/api/v1/search/route";
import { GET as getPriority } from "../app/api/v1/priority/[listName]/route";
import { GET as getRadar } from "../app/api/v1/radar/route";
import { GET as getReplay } from "../app/api/v1/replay/route";
import { GET as getCheckpoints } from "../app/api/v1/replay/checkpoints/route";
import { GET as getOverview } from "../app/api/v1/overview/route";
import { GET as getStatus } from "../app/api/v1/status/route";
import { GET as getHealth } from "../app/api/v1/health/route";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const SCORE_DATE = "2026-10-23";
const PREV_DATE = "2026-10-16";
const LONG_DESC = `A denial of service flaw was found in the packet parser when handling fragmented datagrams with overlapping offsets. A remote attacker can trigger unbounded memory growth and worker starvation by sending a crafted sequence of overlapping fragments over several minutes, leading to sustained CPU pressure, dropped legitimate traffic, additional memory allocator churn, repeated reassembly timeouts, and eventual process termination across affected builds. ${"Padding text to push this description past the excerpt limit. ".repeat(6)}`;

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-api-routes-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return db;
}

afterEach(() => {
  resetDbOverride();
  while (openDbs.length > 0) {
    try {
      (openDbs.pop() as CveDatabase).close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop() as string, { recursive: true, force: true });
  }
});

function seedSyncRuns(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    const insert = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insert.run(
      "cve",
      "2026-10-24T03:50:00.000Z",
      "2026-10-24T03:55:00.000Z",
      "succeeded",
      "rev-test-aaa",
      "hash-cve",
      null,
    );
    insert.run(
      "kev",
      "2026-10-24T03:50:00.000Z",
      "2026-10-24T03:55:00.000Z",
      "succeeded",
      "2026.10.23",
      "hash-kev",
      null,
    );
    insert.run(
      "epss",
      "2026-10-24T03:50:00.000Z",
      "2026-10-24T03:55:00.000Z",
      "succeeded",
      `${SCORE_DATE}@${MODEL}`,
      "hash-epss",
      null,
    );
  });
}

function seedRecord(
  db: CveDatabase,
  cveId: string,
  opts: {
    title?: string | null;
    description?: string;
    lang?: string | null;
    state?: string;
    published?: string | null;
    metrics?: Array<{ origin: string; version: string; baseScore: string; vector?: string }>;
    kev?: string | null;
    epss?: Array<{ date: string; value: string; percentile?: string; model?: string }>;
    rawJson?: string | null;
  } = {},
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        opts.state ?? "PUBLISHED",
        opts.published === undefined ? "2026-10-20T00:00:00.000Z" : opts.published,
        opts.title === undefined ? `Title for ${cveId}` : opts.title,
        opts.description ?? `Description for ${cveId}`,
        opts.lang === undefined ? "en" : opts.lang,
        "rev-test-aaa",
        opts.rawJson === undefined ? null : opts.rawJson,
        STAMP,
        STAMP,
      );
    for (const [index, metric] of (opts.metrics ?? []).entries()) {
      db.handle
        .prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .run(cveId, metric.origin, metric.version, metric.baseScore, metric.vector ?? "", index);
    }
    if (opts.kev !== undefined && opts.kev !== null) {
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
        )
        .run(cveId, opts.kev, "2026.10.23", STAMP);
    }
    for (const row of opts.epss ?? []) {
      db.handle
        .prepare(
          "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
        )
        .run(cveId, row.date, row.model ?? MODEL, row.value, row.percentile ?? "0.90000");
    }
  });
}

/** Five PUBLISHED records covering known, unknown, legacy, zero, and adp-only signals. */
function seedCorpus(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
    description: LONG_DESC,
    published: "2026-10-20T14:02:00.000Z",
    metrics: [
      {
        origin: "CNA",
        version: "4.0",
        baseScore: "9.2",
        vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      },
    ],
    kev: "2026-10-23",
    epss: [{ date: SCORE_DATE, value: "0.1162", percentile: "0.96047" }],
  });
  seedRecord(db, "CVE-2099-0002", {
    description: "",
    lang: null,
    published: "2026-10-19T09:30:00.000Z",
  });
  seedRecord(db, "CVE-2099-0003", {
    published: "2026-10-18T07:45:00.000Z",
    metrics: [
      { origin: "CNA", version: "2.0", baseScore: "10.0", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C" },
    ],
    epss: [{ date: SCORE_DATE, value: "0", percentile: "0.08100" }],
  });
  seedRecord(db, "CVE-2099-0004", { state: "REJECTED" });
  seedRecord(db, "CVE-2099-0005", {
    published: null,
    metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
  });
  seedRecord(db, "CVE-2099-0006", {
    published: "2026-10-17T10:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "7.5", vector: "CVSS:3.1/AV:N" }],
    epss: [
      { date: PREV_DATE, value: "0.10", percentile: "0.90000" },
      { date: SCORE_DATE, value: "0.18", percentile: "0.97500" },
    ],
  });
  seedSyncRuns(db);
}

function seedRadarHistory(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
    description: "A heap overflow in the parser allows remote code execution",
    published: "2026-10-20T00:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
    epss: [{ date: SCORE_DATE, value: "0.1162", percentile: "0.96047" }],
  });
  seedRecord(db, "CVE-2099-0002", {
    description: "A use-after-free in the renderer with moderate impact",
    published: "2026-10-19T00:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.4", vector: "CVSS:3.1/AV:L" }],
  });
  seedSyncRuns(db);
  const pins = {
    cveRevision: "rev-test-aaa",
    kevCatalogDate: "2026-10-22",
    epssScoreDate: SCORE_DATE,
    epssModelVersion: MODEL,
  };
  writeCheckpoint(db, {
    checkpointDate: "2026-08-01",
    observedAt: "2026-08-01T04:00:00.000Z",
    sourcePins: pins,
    policyVersion: "ranking-v1",
  });
  writeCheckpoint(db, {
    checkpointDate: "2026-10-22",
    observedAt: "2026-10-22T04:00:00.000Z",
    sourcePins: pins,
    policyVersion: "ranking-v1",
  });
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", "2026-10-23", "2026.10.23", STAMP);
  });
  writeCheckpoint(db, {
    checkpointDate: "2026-10-23",
    observedAt: "2026-10-23T04:00:00.000Z",
    sourcePins: { ...pins, kevCatalogDate: "2026-10-23" },
    policyVersion: "ranking-v1",
  });
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function rateHeaders(response: Response): Record<string, string | null> {
  return {
    limit: response.headers.get("x-ratelimit-limit"),
    remaining: response.headers.get("x-ratelimit-remaining"),
    reset: response.headers.get("x-ratelimit-reset"),
  };
}

function expectRateHeaders(response: Response): void {
  const headers = rateHeaders(response);
  expect(headers.limit, "X-RateLimit-Limit present").toBe("600");
  expect(Number(headers.remaining)).toBeGreaterThanOrEqual(0);
  expect(Number(headers.reset)).toBeGreaterThanOrEqual(0);
}

function expectProvenance(body: Record<string, unknown>): void {
  const provenance = body.provenance as Record<string, unknown>;
  expect(provenance.rankingPolicyVersion, "policy version in every response").toBe("ranking-v1");
  expect(typeof provenance.generatedAt).toBe("string");
  const sources = provenance.sources as Record<string, Record<string, unknown>>;
  expect(sources.cve?.revision).toBe("rev-test-aaa");
  expect(sources.kev?.catalogVersion).toBe("2026.10.23");
  expect(sources.epss?.scoreDate).toBe(SCORE_DATE);
  expect(sources.epss?.modelVersion).toBe(MODEL);
}

describe("v1 cve list and detail routes", () => {
  it("lists PUBLISHED records in default-priority order with stable cursors", async () => {
    const db = makeDb();
    seedCorpus(db);

    const first = await getCves(new Request("https://radar.test/api/v1/cves?limit=2"));
    expect(first.status).toBe(200);
    expectRateHeaders(first);
    const firstBody = await bodyOf(first);
    expectProvenance(firstBody);
    const firstData = firstBody.data as Array<{ cveId: string }>;
    expect(firstData.map((row) => row.cveId)).toEqual(["CVE-2099-0001", "CVE-2099-0006"]);
    const pagination = firstBody.pagination as {
      limit: number;
      hasMore: boolean;
      nextCursor: string;
    };
    expect(pagination.limit).toBe(2);
    expect(pagination.hasMore).toBe(true);
    expect(typeof pagination.nextCursor).toBe("string");

    const second = await getCves(
      new Request(
        `https://radar.test/api/v1/cves?limit=2&cursor=${encodeURIComponent(pagination.nextCursor)}`,
      ),
    );
    expect(second.status).toBe(200);
    const secondBody = await bodyOf(second);
    const secondData = secondBody.data as Array<{ cveId: string }>;
    expect(secondData.length).toBe(2);
    const seen = new Set([...firstData, ...secondData].map((row) => row.cveId));
    expect(seen.has("CVE-2099-0004"), "REJECTED rows are never listed").toBe(false);
    expect(seen.size).toBe(4);

    const coverage = firstBody.coverage as Record<string, number>;
    expect(coverage.eligibleCohort).toBe(5);
    expect(coverage.unknownDate).toBe(1);
  });

  it("filters by kev/epss/severity and rejects an oversized limit", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const kev = await getCves(new Request("https://radar.test/api/v1/cves?kev=listed"));
    expect(kev.status).toBe(200);
    const kevBody = await bodyOf(kev);
    expect((kevBody.data as Array<{ cveId: string }>).map((row) => row.cveId)).toEqual([
      "CVE-2099-0001",
    ]);

    const oversized = await getCves(new Request("https://radar.test/api/v1/cves?limit=500"));
    expect(oversized.status).toBe(400);
    expectRateHeaders(oversized);
    const errorBody = await bodyOf(oversized);
    expect(errorBody.code).toBe("BAD_LIMIT");
    expect(typeof errorBody.message).toBe("string");
    expectProvenance(errorBody);
  });

  it("serves one record with explicit signals and 404s rejected or missing IDs", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const known = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0001"), {
      params: Promise.resolve({ cveId: "CVE-2099-0001" }),
    });
    expect(known.status).toBe(200);
    expectRateHeaders(known);
    const knownBody = await bodyOf(known);
    expectProvenance(knownBody);
    const data = knownBody.data as Record<string, unknown>;
    expect(data.officialUrl).toBe("https://www.cve.org/CVERecord?id=CVE-2099-0001");
    expect(data.excerptTruncated).toBe(true);
    const epss = data.epss as { status: string; value: number | null };
    expect(epss.status).toBe("known");
    expect(epss.value).toBeCloseTo(0.1162, 4);

    const zero = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0003"), {
      params: Promise.resolve({ cveId: "CVE-2099-0003" }),
    });
    const zeroBody = (await bodyOf(zero)).data as Record<string, unknown>;
    const zeroEpss = zeroBody.epss as { status: string; value: number | null };
    expect(zeroEpss.status).toBe("known");
    expect(zeroEpss.value).toBe(0);

    const unknown = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0002"), {
      params: Promise.resolve({ cveId: "CVE-2099-0002" }),
    });
    const unknownBody = (await bodyOf(unknown)).data as Record<string, unknown>;
    const unknownEpss = unknownBody.epss as { status: string; value: number | null };
    expect(unknownEpss.status).toBe("unknown");
    expect(unknownEpss.value).toBeNull();

    const rejected = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0004"), {
      params: Promise.resolve({ cveId: "CVE-2099-0004" }),
    });
    expect(rejected.status).toBe(404);
    expect((await bodyOf(rejected)).code).toBe("CVE_NOT_FOUND");

    const malformed = await getCveById(new Request("https://radar.test/api/v1/cves/not-a-cve"), {
      params: Promise.resolve({ cveId: "not-a-cve" }),
    });
    expect(malformed.status).toBe(400);
  });
});

describe("epss history trend (detail-only)", () => {
  it("loads latest-model observations per date, oldest first, capped", () => {
    const db = makeDb();
    seedCorpus(db);
    void db;
    db.runBoundedWrite(() => {
      // Same-date second model must lose to the higher model version.
      db.handle
        .prepare(
          "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
        )
        .run("CVE-2099-0006", SCORE_DATE, "v2026.06.99", "0.42", "0.99000");
    });

    const history = loadEpssHistory(db, ["CVE-2099-0006", "CVE-2099-0002", "CVE-2099-9999"]);
    const series = history.get("CVE-2099-0006") ?? [];
    expect(series.map((point) => point.scoreDate)).toEqual([PREV_DATE, SCORE_DATE]);
    expect(series[1]).toMatchObject({
      scoreDate: SCORE_DATE,
      epss: "0.42",
      modelVersion: "v2026.06.99",
    });
    expect(history.has("CVE-2099-0002"), "unscored ids stay absent").toBe(false);
    expect(history.has("CVE-2099-9999"), "unknown ids stay absent").toBe(false);

    const capped = loadEpssHistory(db, ["CVE-2099-0006"], 1);
    expect(capped.get("CVE-2099-0006")?.map((point) => point.scoreDate)).toEqual([SCORE_DATE]);
    expect(loadEpssHistory(db, []).size).toBe(0);
  });

  it("serves the trend on the detail route and null when unknown", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const known = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0006"), {
      params: Promise.resolve({ cveId: "CVE-2099-0006" }),
    });
    expect(known.status).toBe(200);
    const data = ((await bodyOf(known)).data ?? {}) as Record<string, unknown>;
    const history = data.epssHistory as Array<Record<string, string>>;
    expect(history.map((point) => point.scoreDate)).toEqual([PREV_DATE, SCORE_DATE]);
    expect(history[0]).toEqual({ scoreDate: PREV_DATE, epss: "0.10", modelVersion: MODEL });

    const unknown = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0002"), {
      params: Promise.resolve({ cveId: "CVE-2099-0002" }),
    });
    const unknownData = ((await bodyOf(unknown)).data ?? {}) as Record<string, unknown>;
    expect(unknownData.epssHistory).toBeNull();

    // Lists stay compact: the trend is detail-only by documented design.
    const list = await getCves(new Request("https://radar.test/api/v1/cves?limit=5"));
    const rows = ((await bodyOf(list)).data ?? []) as Array<Record<string, unknown>>;
    for (const row of rows) expect("epssHistory" in row).toBe(false);
  });
});

describe("v1 search route", () => {
  it("requires q and returns excerpts with official links", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const missing = await getSearch(new Request("https://radar.test/api/v1/search"));
    expect(missing.status).toBe(400);
    expect((await bodyOf(missing)).code).toBe("BAD_QUERY");

    const short = await getSearch(new Request("https://radar.test/api/v1/search?q=x"));
    expect(short.status).toBe(400);

    const hostile = await getSearch(
      new Request("https://radar.test/api/v1/search?q=%27%20OR%20%271%27%3D%271"),
    );
    expect(hostile.status).toBe(400);
    expect((await bodyOf(hostile)).code).toBe("BAD_QUERY");

    const match = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser"),
    );
    expect(match.status).toBe(200);
    expectRateHeaders(match);
    const matchBody = await bodyOf(match);
    expectProvenance(matchBody);
    expect(matchBody.q).toBe("packet parser");
    const data = matchBody.data as Array<Record<string, unknown>>;
    expect(data.length).toBeGreaterThan(0);
    expect(data[0]?.officialUrl).toBe(
      `https://www.cve.org/CVERecord?id=${data[0]?.cveId as string}`,
    );
    expect(typeof data[0]?.excerptStatus).toBe("string");
  });
});

describe("v1 priority routes", () => {
  it("serves the four named views with ordering, deltas, and 404s unknown lists", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    for (const list of ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"]) {
      const response = await getPriority(
        new Request(`https://radar.test/api/v1/priority/${list}`),
        {
          params: Promise.resolve({ listName: list }),
        },
      );
      expect(response.status, list).toBe(200);
      expectRateHeaders(response);
      const body = await bodyOf(response);
      expectProvenance(body);
      expect(body.list).toBe(list);
      expect(Array.isArray(body.ordering)).toBe(true);
    }

    const exploited = await getPriority(
      new Request("https://radar.test/api/v1/priority/known-exploited"),
      { params: Promise.resolve({ listName: "known-exploited" }) },
    );
    const exploitedBody = await bodyOf(exploited);
    expect(exploitedBody.ordering).toEqual(["kev-dateAdded-desc", "cveId-asc"]);
    expect((exploitedBody.data as Array<{ cveId: string }>).map((row) => row.cveId)).toEqual([
      "CVE-2099-0001",
    ]);
    expect(exploitedBody.deltaPp).toBeNull();

    const rising = await getPriority(
      new Request("https://radar.test/api/v1/priority/rising-forecast"),
      { params: Promise.resolve({ listName: "rising-forecast" }) },
    );
    const risingBody = await bodyOf(rising);
    const risingData = risingBody.data as Array<{ cveId: string }>;
    expect(risingData.map((row) => row.cveId)).toEqual(["CVE-2099-0006"]);
    expect(risingBody.deltaPp).toEqual([8]);

    const missing = await getPriority(
      new Request("https://radar.test/api/v1/priority/most-discussed"),
      { params: Promise.resolve({ listName: "most-discussed" }) },
    );
    expect(missing.status).toBe(404);
    expect((await bodyOf(missing)).code).toBe("LIST_NOT_FOUND");
  });
});

describe("v1 radar and replay routes", () => {
  it("lists observed change events newest first with before/after evidence", async () => {
    const db = makeDb();
    seedRadarHistory(db);
    void db;

    const response = await getRadar(new Request("https://radar.test/api/v1/radar"));
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const body = await bodyOf(response);
    expectProvenance(body);
    const data = body.data as Array<Record<string, unknown>>;
    const kevAdded = data.find((event) => event.kind === "kev-added");
    expect(kevAdded, "KEV addition is observed as a source change").toBeDefined();
    expect(kevAdded?.cveId).toBe("CVE-2099-0001");
    const changes = kevAdded?.changes as Array<{ field: string; before: unknown; after: unknown }>;
    expect(changes).toContainEqual({ field: "kev.listed", before: "false", after: "true" });

    const filtered = await getRadar(
      new Request("https://radar.test/api/v1/radar?kind=kev-added&cveId=CVE-2099-0001"),
    );
    expect(filtered.status).toBe(200);
    const filteredData = (await bodyOf(filtered)).data as Array<Record<string, unknown>>;
    expect(filteredData.length).toBeGreaterThan(0);
    expect(
      filteredData.every((event) => event.kind === "kev-added" && event.cveId === "CVE-2099-0001"),
    ).toBe(true);

    const badKind = await getRadar(new Request("https://radar.test/api/v1/radar?kind=nope"));
    expect(badKind.status).toBe(400);
  });

  it("lists retained checkpoints and replays a view or fails with the named reason", async () => {
    const db = makeDb();
    seedRadarHistory(db);
    void db;

    const listed = await getCheckpoints(
      new Request("https://radar.test/api/v1/replay/checkpoints"),
    );
    expect(listed.status).toBe(200);
    const listedBody = await bodyOf(listed);
    expectProvenance(listedBody);
    expect(listedBody.retainedFrom).toBe("2026-08-01");
    expect(listedBody.retainedTo).toBe("2026-10-23");
    const manifests = listedBody.data as Array<{ checkpointDate: string; expired: boolean }>;
    expect(manifests[0]?.checkpointDate).toBe("2026-10-23");
    expect(manifests.find((row) => row.checkpointDate === "2026-08-01")?.expired).toBe(true);

    const replayed = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-10-23&view=highest-forecast"),
    );
    expect(replayed.status).toBe(200);
    const replayedBody = await bodyOf(replayed);
    expectProvenance(replayedBody);
    expect(replayedBody.checkpointDate).toBe("2026-10-23");
    expect(replayedBody.rankingPolicyVersion).toBe("ranking-v1");
    const replayedData = replayedBody.data as Array<{ cveId: string }>;
    expect(replayedData.map((row) => row.cveId)).toContain("CVE-2099-0001");

    const missing = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-10-21&view=highest-forecast"),
    );
    expect(missing.status).toBe(404);
    const missingBody = await bodyOf(missing);
    expect(missingBody.code).toBe("REPLAY_UNAVAILABLE");
    const details = missingBody.details as { reason: string };
    expect(typeof details.reason).toBe("string");

    const expired = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-08-01&view=highest-forecast"),
    );
    expect(expired.status).toBe(404);
    const expiredBody = await bodyOf(expired);
    expect(expiredBody.code).toBe("REPLAY_UNAVAILABLE");
    expect((expiredBody.details as { reason: string }).reason).toBe("expired");
  });
});

describe("v1 overview, status, and health routes", () => {
  it("aggregates publication buckets with an explicit unknown-date count", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const response = await getOverview(
      new Request("https://radar.test/api/v1/overview?bucket=month&months=2"),
    );
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const body = await bodyOf(response);
    expectProvenance(body);
    expect(body.bucket).toBe("month");
    expect(body.dateBasis).toBe("publishedAt-utc");
    expect(body.unknownDateCount).toBe(1);
    const buckets = body.buckets as Array<{ bucketStart: string; count: number }>;
    expect(buckets.length).toBe(2);

    const badBucket = await getOverview(
      new Request("https://radar.test/api/v1/overview?bucket=year"),
    );
    expect(badBucket.status).toBe(400);
  });

  it("reports freshness, cohorts, notices, and liveness from the same snapshots", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const status = await getStatus(new Request("https://radar.test/api/v1/status"));
    expect(status.status).toBe(200);
    const statusBody = await bodyOf(status);
    expect(statusBody.rankingPolicyVersion).toBe("ranking-v1");
    const cohorts = statusBody.cohorts as Record<string, number>;
    expect(cohorts.published).toBe(5);
    expect(cohorts.kevListed).toBe(1);
    const notices = statusBody.notices as string[];
    expect(notices).toHaveLength(3);
    expectProvenance(statusBody);

    const health = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(health.status).toBe(200);
    const healthBody = await bodyOf(health);
    expect(healthBody.status).toBe("ok");
    expect(healthBody.version).toBe("v1");
    expectProvenance(healthBody);
  });

  it("reports initializing health when no accepted snapshot exists", async () => {
    makeDb();
    const health = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(health.status).toBe(200);
    expect((await bodyOf(health)).status).toBe("initializing");
  });
});
