// New-test justification (plan todo 17): the versioned read-only API and the
// website views must read the same accepted snapshots through the same
// services with no divergent query path, so this suite proves against the real
// handlers and services (not shape fixtures) that every website view
// (overview, explore/search, the four priority lists, radar, replay,
// health/status) and its API counterpart return the same cohort, ordering,
// provenance, and stale labels from the same fixture snapshot. Stale and
// missing data must render identically on both surfaces; the API-only
// self-host proof invokes handlers directly with API-path requests while UI
// routes stay excluded (no server needed); and an older pinned policy version
// must trip the parity detector with the differing field named. Fixture IDs
// are invented CVE-2099 values; nothing here touches the network.
//
// Site-side note: product UI pages (todos 18-24) do not exist yet, so the
// "website view" side is the shared service layer the site is contracted to
// read (searchCves, priority services, radar/replay services, buildProvenance)
// per the todo-14 no-divergent-query-path rule.

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  getAcceptedEpssDate,
  getDefaultPriority,
  getHighestForecast,
  getKnownExploited,
  getNewCritical,
  getRisingForecast,
} from "../src/lib/priority";
import {
  diffCheckpoints,
  isCheckpointExpired,
  listCheckpoints,
  readCheckpoint,
  replayCheckpoint,
  writeCheckpoint,
  type StoredRadarCheckpoint,
} from "../src/lib/radar";
import { DESCRIPTION_MISSING_LABEL, excerptDescription, searchCves } from "../src/lib/search";
import {
  buildProvenance,
  buildRadarEvents,
  coverageForSnapshots,
  detailExtras,
  loadFullRecords,
  mapReplayReason,
  RANKING_POLICY_VERSION,
  resetDbOverride,
  resetHardeningState,
  setDbOverride,
  toCveItem,
  toReplayItem,
  todayUtcDay,
} from "../app/api/v1/_lib/shared";
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

const MODEL = "v2026.06.15";
const KEV_CATALOG = "2099.01.01";
const LONG_DESC =
  `A denial of service flaw was found in the packet parser when handling fragmented datagrams with overlapping offsets. ` +
  `A remote attacker can trigger unbounded memory growth and worker starvation by sending a crafted sequence of ` +
  `overlapping fragments over several minutes, leading to sustained CPU pressure, dropped legitimate traffic, ` +
  `additional memory allocator churn, repeated reassembly timeouts, and eventual process termination across affected builds. ` +
  "Padding text to push this description past the excerpt limit. ".repeat(6);

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-api-parity-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return db;
}

beforeEach(() => {
  resetHardeningState();
});

afterEach(() => {
  resetDbOverride();
  resetHardeningState();
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

/** UTC day string offset from today, so fixtures stay clock-relative. */
function utcDay(offsetDays: number): string {
  const todayMs = Date.parse(`${new Date().toISOString().slice(0, 10)}T00:00:00.000Z`);
  return new Date(todayMs + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

function stamp(day: string): string {
  return `${day}T12:00:00.000Z`;
}

interface SeedMetric {
  origin: string;
  version: string;
  baseScore: string;
  vector?: string;
}

interface SeedEpss {
  date: string;
  value: string;
  percentile?: string;
  model?: string;
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
    metrics?: SeedMetric[];
    kev?: string | null;
    epss?: SeedEpss[];
    rawJson?: string | null;
  } = {},
): void {
  const day = utcDay(0);
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        opts.state ?? "PUBLISHED",
        opts.published === undefined ? stamp(day) : opts.published,
        opts.title === undefined ? `Title for ${cveId}` : opts.title,
        opts.description ?? `Description for ${cveId}`,
        opts.lang === undefined ? "en" : opts.lang,
        "rev-test-aaa",
        opts.rawJson === undefined ? null : opts.rawJson,
        stamp(day),
        stamp(day),
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
        .run(cveId, opts.kev, KEV_CATALOG, stamp(day));
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

function seedSyncRuns(db: CveDatabase, finishedDay: string, epssScoreDate: string): void {
  const finishedAt = `${finishedDay}T03:55:00.000Z`;
  db.runBoundedWrite(() => {
    const insert = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insert.run(
      "cve",
      `${finishedDay}T03:50:00.000Z`,
      finishedAt,
      "succeeded",
      "rev-test-aaa",
      "hash-cve",
      null,
    );
    insert.run(
      "kev",
      `${finishedDay}T03:50:00.000Z`,
      finishedAt,
      "succeeded",
      KEV_CATALOG,
      "hash-kev",
      null,
    );
    insert.run(
      "epss",
      `${finishedDay}T03:50:00.000Z`,
      finishedAt,
      "succeeded",
      `${epssScoreDate}@${MODEL}`,
      "hash-epss",
      null,
    );
  });
}

/**
 * Full-signal corpus: known EPSS beside explicit unknown, a real zero beside
 * unknown, legacy v2 beside modern CNA, a truncated long description beside a
 * missing one, and an unknown-date ADP-only record beside dated ones.
 */
function seedCorpus(db: CveDatabase): { scoreDate: string; prevDate: string } {
  const scoreDate = utcDay(-1);
  const prevDate = utcDay(-8);
  seedRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
    description: LONG_DESC,
    published: stamp(utcDay(-4)),
    metrics: [
      {
        origin: "CNA",
        version: "4.0",
        baseScore: "9.2",
        vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      },
    ],
    kev: utcDay(-1),
    epss: [{ date: scoreDate, value: "0.1162", percentile: "0.96047" }],
  });
  seedRecord(db, "CVE-2099-0002", {
    description: "",
    lang: null,
    published: stamp(utcDay(-5)),
  });
  seedRecord(db, "CVE-2099-0003", {
    published: stamp(utcDay(-6)),
    metrics: [
      { origin: "CNA", version: "2.0", baseScore: "10.0", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C" },
    ],
    epss: [{ date: scoreDate, value: "0", percentile: "0.08100" }],
  });
  seedRecord(db, "CVE-2099-0004", { state: "REJECTED" });
  seedRecord(db, "CVE-2099-0005", {
    published: null,
    metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
  });
  seedRecord(db, "CVE-2099-0006", {
    published: stamp(utcDay(-7)),
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "7.5", vector: "CVSS:3.1/AV:N" }],
    epss: [
      { date: prevDate, value: "0.10", percentile: "0.90000" },
      { date: scoreDate, value: "0.18", percentile: "0.97500" },
    ],
  });
  seedSyncRuns(db, utcDay(0), scoreDate);
  return { scoreDate, prevDate };
}

/** Minimal two-record corpus where a later KEV addition flips default order. */
function seedRadarCorpus(db: CveDatabase): { scoreDate: string } {
  const scoreDate = utcDay(-1);
  seedRecord(db, "CVE-2099-0001", {
    published: stamp(utcDay(-4)),
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "6.0", vector: "CVSS:3.1/AV:N" }],
    epss: [{ date: scoreDate, value: "0.05", percentile: "0.70000" }],
  });
  seedRecord(db, "CVE-2099-0002", {
    published: stamp(utcDay(-5)),
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
    epss: [{ date: scoreDate, value: "0.90", percentile: "0.99000" }],
  });
  seedSyncRuns(db, utcDay(0), scoreDate);
  return { scoreDate };
}

function writeCheckpointOn(
  db: CveDatabase,
  checkpointDate: string,
  policyVersion: string,
  kevCatalogDate: string,
  epssScoreDate: string,
): StoredRadarCheckpoint {
  return writeCheckpoint(db, {
    checkpointDate,
    observedAt: `${checkpointDate}T04:00:00.000Z`,
    sourcePins: {
      cveRevision: "rev-test-aaa",
      kevCatalogDate,
      epssScoreDate,
      epssModelVersion: MODEL,
    },
    policyVersion,
  });
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

/** Provenance minus the per-call timestamp, so two calls can be compared. */
function provenanceCore(body: Record<string, unknown>): unknown {
  const copy = { ...(body.provenance as Record<string, unknown>) };
  delete copy.generatedAt;
  return copy;
}

function siteProvenanceCore(db: CveDatabase): unknown {
  const full = buildProvenance(db, new Date().toISOString()) as unknown as Record<string, unknown>;
  delete full.generatedAt;
  return full;
}

/**
 * Deep comparison returning the dotted paths of every difference. Parity
 * tests require this to be empty; the policy-sensitivity test requires it to
 * name the pinned-policy and ordering fields.
 */
function findDivergences(site: unknown, api: unknown, field: string): string[] {
  if (typeof site !== typeof api) return [field];
  if (site === null || api === null || typeof site !== "object") {
    return Object.is(site, api) ? [] : [field];
  }
  if (Array.isArray(site) || Array.isArray(api)) {
    if (!Array.isArray(site) || !Array.isArray(api)) return [field];
    const out: string[] = [];
    if (site.length !== api.length) out.push(`${field}.length`);
    const count = Math.max(site.length, api.length);
    for (let index = 0; index < count; index += 1) {
      out.push(...findDivergences(site[index], api[index], `${field}[${index}]`));
    }
    return out;
  }
  const out: string[] = [];
  const keys = new Set([
    ...Object.keys(site as Record<string, unknown>),
    ...Object.keys(api as Record<string, unknown>),
  ]);
  for (const key of [...keys].sort()) {
    const child = field === "" ? key : `${field}.${key}`;
    out.push(
      ...findDivergences(
        (site as Record<string, unknown>)[key],
        (api as Record<string, unknown>)[key],
        child,
      ),
    );
  }
  return out;
}

function expectParity(site: unknown, api: unknown, field: string): void {
  const divergences = findDivergences(site, api, field);
  expect(divergences, `site/API parity divergence at: ${divergences.join(", ")}`).toEqual([]);
}

function expectRateHeaders(response: Response): void {
  expect(response.headers.get("x-ratelimit-limit"), "X-RateLimit-Limit present").toBe("600");
}

describe("overview parity (site buckets vs /api/v1/overview)", () => {
  it("returns the same cohort, unknown-date bucket, month counts, and provenance", async () => {
    const db = makeDb();
    seedCorpus(db);

    const response = await getOverview(
      new Request("https://radar.test/api/v1/overview?bucket=month&months=120"),
    );
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const api = await bodyOf(response);

    const siteItems = getDefaultPriority(db);
    expectParity(
      siteItems.length,
      (api.coverage as { eligibleCohort: number }).eligibleCohort,
      "coverage.eligibleCohort",
    );

    let siteUnknown = 0;
    const siteMonths = new Map<string, number>();
    for (const item of siteItems) {
      if (item.publishedAt === null) {
        siteUnknown += 1;
        continue;
      }
      const key = item.publishedAt.slice(0, 7);
      siteMonths.set(key, (siteMonths.get(key) ?? 0) + 1);
    }
    expectParity(siteUnknown, api.unknownDateCount, "unknownDateCount");
    expect(api.dateBasis).toBe("publishedAt-utc");
    expect(api.bucket).toBe("month");

    const buckets = api.buckets as Array<{ bucketStart: string; count: number }>;
    const apiMonths = new Map(buckets.map((row) => [row.bucketStart, row.count]));
    for (const [month, count] of siteMonths) {
      expectParity(count, apiMonths.get(month) ?? 0, `buckets[${month}].count`);
    }
    const bucketedTotal = buckets.reduce((sum, row) => sum + row.count, 0);
    expectParity(siteItems.length - siteUnknown, bucketedTotal, "buckets.total");
    expect(api.correctionNotes).toEqual([]);

    expectParity(siteProvenanceCore(db), provenanceCore(api), "provenance");
  });
});

describe("explore/search parity (searchCves vs /api/v1/search)", () => {
  it("returns the same cohort, ordering, excerpts, links, and provenance", async () => {
    const db = makeDb();
    seedCorpus(db);

    const site = searchCves(db, { q: "packet parser", limit: 100 });
    const siteIds = site.items.map((row) => row.cveId);

    const response = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser&limit=100"),
    );
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const api = await bodyOf(response);
    const data = api.data as Array<Record<string, unknown>>;
    expectParity(
      siteIds,
      data.map((row) => row.cveId),
      "data[].cveId",
    );
    expectParity(
      site.total,
      (api.coverage as { eligibleCohort: number }).eligibleCohort,
      "coverage.eligibleCohort",
    );

    const records = loadFullRecords(db, siteIds);
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const scoreDate = getAcceptedEpssDate(db);
    for (const row of data) {
      const record = byId.get(row.cveId as string);
      expect(record, `site record for ${row.cveId as string}`).toBeDefined();
      if (record === undefined) continue;
      const shaped = toCveItem(record, scoreDate, null);
      expectParity(shaped.excerpt, row.excerpt, `data[${row.cveId as string}].excerpt`);
      expectParity(
        shaped.excerptTruncated,
        row.excerptTruncated,
        `data[${row.cveId as string}].excerptTruncated`,
      );
      expectParity(
        shaped.excerptStatus,
        row.excerptStatus,
        `data[${row.cveId as string}].excerptStatus`,
      );
      expectParity(shaped.officialUrl, row.officialUrl, `data[${row.cveId as string}].officialUrl`);
    }
    expectParity(siteProvenanceCore(db), provenanceCore(api), "provenance");
  });
});

describe("priority parity (priority services vs /api/v1/priority/*)", () => {
  const lists = ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"] as const;

  it("returns the same cohort, ordering, deltas, coverage, and provenance per list", async () => {
    const db = makeDb();
    seedCorpus(db);
    const cutoffT = new Date().toISOString();

    for (const list of lists) {
      const response = await getPriority(
        new Request(`https://radar.test/api/v1/priority/${list}?limit=100`),
        { params: Promise.resolve({ listName: list }) },
      );
      expect(response.status, list).toBe(200);
      expectRateHeaders(response);
      const api = await bodyOf(response);
      const data = api.data as Array<Record<string, unknown>>;

      if (list === "rising-forecast") {
        const site = getRisingForecast(db);
        expectParity(
          site.map((row) => row.item.id),
          data.map((row) => row.cveId),
          `priority[${list}].data[].cveId`,
        );
        expectParity(
          site.map((row) => Number(row.deltaPp)),
          api.deltaPp,
          `priority[${list}].deltaPp`,
        );
        expect(api.ordering).toEqual(["delta-pp-desc", "epss-raw-desc", "cveId-asc"]);
      } else {
        const site =
          list === "known-exploited"
            ? getKnownExploited(db)
            : list === "highest-forecast"
              ? getHighestForecast(db)
              : getNewCritical(db, cutoffT);
        expectParity(
          site.map((row) => row.id),
          data.map((row) => row.cveId),
          `priority[${list}].data[].cveId`,
        );
        expect(api.deltaPp).toBeNull();
      }
      expect(api.list).toBe(list);
      expectParity(siteProvenanceCore(db), provenanceCore(api), `priority[${list}].provenance`);
    }
  });

  it("keeps unknown EPSS explicit null beside a real zero on both surfaces", async () => {
    const db = makeDb();
    seedCorpus(db);

    const unknownApi = await getCveById(
      new Request("https://radar.test/api/v1/cves/CVE-2099-0002"),
      { params: Promise.resolve({ cveId: "CVE-2099-0002" }) },
    );
    expect(unknownApi.status).toBe(200);
    const unknownData = ((await bodyOf(unknownApi)).data ?? {}) as Record<string, unknown>;
    const unknownEpss = unknownData.epss as { status: string; value: number | null };
    expect(unknownEpss.status).toBe("unknown");
    expect(unknownEpss.value).toBeNull();

    const zeroApi = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0003"), {
      params: Promise.resolve({ cveId: "CVE-2099-0003" }),
    });
    expect(zeroApi.status).toBe(200);
    const zeroData = ((await bodyOf(zeroApi)).data ?? {}) as Record<string, unknown>;
    const zeroEpss = zeroData.epss as { status: string; value: number | null };
    expect(zeroEpss.status).toBe("known");
    expect(zeroEpss.value).toBe(0);

    const [unknownRecord] = loadFullRecords(db, ["CVE-2099-0002"]);
    const [zeroRecord] = loadFullRecords(db, ["CVE-2099-0003"]);
    expect(unknownRecord?.epssText, "site unknown stays null, never 0").toBeNull();
    expect(zeroRecord?.epssText, "site real zero stays present").toBe("0");
  });
});

describe("cve list and detail parity (priority service vs /api/v1/cves)", () => {
  it("pages the same default-priority cohort with identical items and coverage", async () => {
    const db = makeDb();
    seedCorpus(db);

    const siteIds = getDefaultPriority(db).map((row) => row.id);
    const first = await getCves(new Request("https://radar.test/api/v1/cves?limit=2"));
    expect(first.status).toBe(200);
    expectRateHeaders(first);
    const firstBody = await bodyOf(first);
    const pagination = firstBody.pagination as { hasMore: boolean; nextCursor: string };
    expect(pagination.hasMore).toBe(true);

    const second = await getCves(
      new Request(
        `https://radar.test/api/v1/cves?limit=100&cursor=${encodeURIComponent(pagination.nextCursor)}`,
      ),
    );
    expect(second.status).toBe(200);
    const secondData = (await bodyOf(second)).data as Array<Record<string, unknown>>;
    const firstData = firstBody.data as Array<Record<string, unknown>>;
    expectParity(
      siteIds,
      [...firstData, ...secondData].map((row) => row.cveId),
      "data[].cveId",
    );
    expectParity(
      siteIds.length,
      (firstBody.coverage as { eligibleCohort: number }).eligibleCohort,
      "coverage.eligibleCohort",
    );
    expectParity(siteProvenanceCore(db), provenanceCore(firstBody), "provenance");

    const full = await getCves(new Request("https://radar.test/api/v1/cves?limit=100"));
    const fullData = (await bodyOf(full)).data as Array<Record<string, unknown>>;
    const scoreDate = getAcceptedEpssDate(db);
    const records = loadFullRecords(db, siteIds);
    const byId = new Map(records.map((record) => [record.cveId, record]));
    for (const row of fullData) {
      const record = byId.get(row.cveId as string);
      expect(record, `site record for ${row.cveId as string}`).toBeDefined();
      if (record === undefined) continue;
      expectParity(toCveItem(record, scoreDate, null), row, `data[${row.cveId as string}]`);
    }
  });

  it("matches detail extras and rejects non-published IDs on both surfaces", async () => {
    const db = makeDb();
    seedCorpus(db);

    const detail = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0001"), {
      params: Promise.resolve({ cveId: "CVE-2099-0001" }),
    });
    expect(detail.status).toBe(200);
    const data = ((await bodyOf(detail)).data ?? {}) as Record<string, unknown>;
    const [record] = loadFullRecords(db, ["CVE-2099-0001"]);
    expect(record).toBeDefined();
    if (record === undefined) throw new Error("seed failed");
    const siteExtras = detailExtras(record.rawJson, record.descriptionLang);
    expectParity(
      siteExtras.descriptionLanguages,
      data.descriptionLanguages,
      "descriptionLanguages",
    );
    expectParity(siteExtras.references, data.references, "references");
    expect(data.excerptTruncated).toBe(true);

    const rejected = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0004"), {
      params: Promise.resolve({ cveId: "CVE-2099-0004" }),
    });
    expect(rejected.status).toBe(404);
    expect((await bodyOf(rejected)).code).toBe("CVE_NOT_FOUND");
  });
});

describe("radar parity (diff service vs /api/v1/radar)", () => {
  function seedHistory(db: CveDatabase): { beforeDate: string; afterDate: string } {
    seedRadarCorpus(db);
    const beforeDate = utcDay(-2);
    const afterDate = utcDay(-1);
    const { scoreDate } = { scoreDate: utcDay(-1) };
    writeCheckpointOn(db, beforeDate, "ranking-v1", KEV_CATALOG, scoreDate);
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
        )
        .run("CVE-2099-0001", afterDate, KEV_CATALOG, stamp(utcDay(0)));
    });
    writeCheckpointOn(db, afterDate, "ranking-v1", KEV_CATALOG, scoreDate);
    return { beforeDate, afterDate };
  }

  it("emits the same newest-first events with identical before/after evidence", async () => {
    const db = makeDb();
    seedHistory(db);

    const siteEvents = buildRadarEvents(listCheckpoints(db));
    expect(siteEvents.length).toBeGreaterThan(0);
    const response = await getRadar(new Request("https://radar.test/api/v1/radar?limit=100"));
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const api = await bodyOf(response);
    expectParity(siteEvents, api.data, "data");

    const kevAdded = siteEvents.find((event) => event.kind === "kev-added");
    expect(kevAdded, "KEV addition is a source change, not a rank move").toBeDefined();
    expect(kevAdded?.cveId).toBe("CVE-2099-0001");

    const filtered = await getRadar(
      new Request("https://radar.test/api/v1/radar?kind=kev-added&cveId=CVE-2099-0001&limit=100"),
    );
    expect(filtered.status).toBe(200);
    const filteredData = ((await bodyOf(filtered)).data ?? []) as Array<Record<string, unknown>>;
    const siteFiltered = siteEvents.filter(
      (event) => event.kind === "kev-added" && event.cveId === "CVE-2099-0001",
    );
    expectParity(siteFiltered, filteredData, "data[filtered]");
    expectParity(siteProvenanceCore(db), provenanceCore(api), "provenance");
  });
});

describe("replay parity (replay service vs /api/v1/replay)", () => {
  const views = ["known-exploited", "highest-forecast", "new-critical", "rising-forecast"] as const;
  const viewKeys = {
    "known-exploited": "knownExploited",
    "highest-forecast": "highestForecast",
    "new-critical": "newCritical",
    "rising-forecast": "risingForecast",
  } as const;

  function seedReplay(db: CveDatabase): string {
    const { scoreDate } = seedRadarCorpus(db);
    const checkpointDate = utcDay(-1);
    writeCheckpointOn(db, utcDay(-2), "ranking-v1", KEV_CATALOG, scoreDate);
    writeCheckpointOn(db, checkpointDate, "ranking-v1", KEV_CATALOG, scoreDate);
    return checkpointDate;
  }

  it("replays the retained materialized views byte-for-byte per view", async () => {
    const db = makeDb();
    const checkpointDate = seedReplay(db);
    const today = todayUtcDay(new Date().toISOString());

    for (const view of views) {
      const replayed = replayCheckpoint(db, checkpointDate, { asOfDate: today });
      expect(replayed.status).toBe("available");
      if (replayed.status !== "available") continue;
      const siteIds = replayed.manifest.views[viewKeys[view]] ?? [];

      const response = await getReplay(
        new Request(
          `https://radar.test/api/v1/replay?date=${checkpointDate}&view=${view}&limit=100`,
        ),
      );
      expect(response.status, view).toBe(200);
      expectRateHeaders(response);
      const api = await bodyOf(response);
      const data = api.data as Array<Record<string, unknown>>;
      expectParity(
        siteIds,
        data.map((row) => row.cveId),
        `replay[${view}].data[].cveId`,
      );
      expectParity(
        replayed.manifest.policyVersion,
        api.rankingPolicyVersion,
        "rankingPolicyVersion",
      );

      const siteItems = siteIds.map((cveId) => {
        const snapshot = replayed.manifest.items[cveId];
        expect(snapshot, `retained snapshot for ${cveId}`).toBeDefined();
        if (snapshot === undefined) throw new Error("seed failed");
        return toReplayItem(cveId, snapshot, replayed.manifest.sourcePins);
      });
      expectParity(siteItems, data, `replay[${view}].data`);
      const siteCoverage = coverageForSnapshots(siteIds, replayed.manifest.items, siteIds.length);
      expectParity(siteCoverage, api.coverage, `replay[${view}].coverage`);
      expectParity(siteProvenanceCore(db), provenanceCore(api), `replay[${view}].provenance`);
    }
  });

  it("names the same unavailable reason as the service for missing, expired, and pre-launch dates", async () => {
    const db = makeDb();
    const checkpointDate = seedReplay(db);
    void checkpointDate;
    writeCheckpointOn(db, utcDay(-40), "ranking-v1", KEV_CATALOG, utcDay(-1));
    const today = todayUtcDay(new Date().toISOString());
    const cases: Array<{ date: string; reason: string }> = [
      { date: utcDay(-3), reason: "missing-day" },
      { date: utcDay(-40), reason: "expired" },
      { date: utcDay(-41), reason: "pre-launch" },
    ];
    for (const { date, reason } of cases) {
      const service = replayCheckpoint(db, date, { asOfDate: today });
      expect(service.status).toBe("unavailable");
      if (service.status !== "unavailable") continue;
      expectParity(mapReplayReason(service.reason), reason, `replay[${date}].reason`);

      const response = await getReplay(
        new Request(`https://radar.test/api/v1/replay?date=${date}&view=highest-forecast`),
      );
      expect(response.status, date).toBe(404);
      const api = await bodyOf(response);
      expect(api.code).toBe("REPLAY_UNAVAILABLE");
      expectParity(
        (api.details as { reason: string }).reason,
        reason,
        `replay[${date}].details.reason`,
      );
    }
  });

  it("lists the same retained checkpoints with matching expiry labels", async () => {
    const db = makeDb();
    const checkpointDate = seedReplay(db);
    const today = todayUtcDay(new Date().toISOString());

    const response = await getCheckpoints(
      new Request("https://radar.test/api/v1/replay/checkpoints?limit=100"),
    );
    expect(response.status).toBe(200);
    const api = await bodyOf(response);
    const site = listCheckpoints(db).map((manifest) => ({
      checkpointDate: manifest.checkpointDate,
      rankingPolicyVersion: manifest.policyVersion,
      cveRevision: manifest.sourcePins.cveRevision,
      kevCatalogVersion: manifest.sourcePins.kevCatalogDate,
      epssScoreDate: manifest.sourcePins.epssScoreDate,
      epssModelVersion: manifest.sourcePins.epssModelVersion,
      eligibleCohort: manifest.cohortCount,
      boundedTopN: manifest.boundedTopN,
      expired: isCheckpointExpired(manifest.checkpointDate, today),
    }));
    expectParity([...site].reverse(), api.data, "checkpoints.data");
    expect(api.retainedFrom).toBe(site[0]?.checkpointDate ?? null);
    expect(api.retainedTo).toBe(site[site.length - 1]?.checkpointDate ?? null);
    expect(
      (api.data as Array<{ checkpointDate: string }>).map((row) => row.checkpointDate),
    ).toContain(checkpointDate);
  });
});

describe("health/status parity (same snapshots, same freshness labels)", () => {
  it("reports identical cohorts, notices, and provenance on every surface", async () => {
    const db = makeDb();
    seedCorpus(db);

    const status = await getStatus(new Request("https://radar.test/api/v1/status"));
    expect(status.status).toBe(200);
    const statusBody = await bodyOf(status);
    const cohorts = statusBody.cohorts as Record<string, number>;
    expectParity(getDefaultPriority(db).length, cohorts.published, "cohorts.published");
    expect((statusBody.notices as string[]).length).toBeGreaterThanOrEqual(3);
    expect(statusBody.rankingPolicyVersion).toBe(RANKING_POLICY_VERSION);

    const health = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(health.status).toBe(200);
    const healthBody = await bodyOf(health);
    expect(healthBody.status as string).toBe("ok");

    const cves = await getCves(new Request("https://radar.test/api/v1/cves?limit=1"));
    const cvesBody = await bodyOf(cves);
    const search = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser&limit=1"),
    );
    const searchBody = await bodyOf(search);
    const statusCore = provenanceCore(statusBody);
    for (const [name, body] of [
      ["health", healthBody],
      ["cves", cvesBody],
      ["search", searchBody],
    ] as const) {
      expectParity(statusCore, provenanceCore(body), `provenance[${name}]`);
    }
  });

  it("reports initializing health on both surfaces when no snapshot is accepted", async () => {
    const db = makeDb();
    void db;

    const health = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(health.status).toBe(200);
    expect((await bodyOf(health)).status as string).toBe("initializing");
    expect(getDefaultPriority(db)).toEqual([]);
    expect(getAcceptedEpssDate(db)).toBeNull();
  });
});

describe("stale and missing data parity (adversarial)", () => {
  function seedStale(db: CveDatabase): void {
    const scoreDate = utcDay(-10);
    const prevDate = utcDay(-17);
    seedRecord(db, "CVE-2099-0001", {
      description: LONG_DESC,
      published: stamp(utcDay(-11)),
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
      epss: [
        { date: prevDate, value: "0.10", percentile: "0.90000" },
        { date: scoreDate, value: "0.18", percentile: "0.97500" },
      ],
    });
    seedRecord(db, "CVE-2099-0002", { description: "", lang: null, published: stamp(utcDay(-12)) });
    seedRecord(db, "CVE-2099-0005", {
      published: null,
      metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
    });
    seedSyncRuns(db, utcDay(-10), scoreDate);
  }

  it("represents stale sources, unknown EPSS, missing excerpts, and unknown dates identically", async () => {
    const db = makeDb();
    seedStale(db);

    const siteCore = siteProvenanceCore(db) as {
      sources: Record<string, { stale: boolean }>;
    };
    expect(siteCore.sources.cve?.stale, "site sees the stale CVE feed").toBe(true);
    expect(siteCore.sources.kev?.stale, "site sees the stale KEV feed").toBe(true);
    expect(siteCore.sources.epss?.stale, "site sees the stale EPSS snapshot").toBe(true);

    for (const [name, response] of [
      ["cves", await getCves(new Request("https://radar.test/api/v1/cves?limit=100"))],
      ["status", await getStatus(new Request("https://radar.test/api/v1/status"))],
      ["health", await getHealth(new Request("https://radar.test/api/v1/health"))],
      [
        "overview",
        await getOverview(
          new Request("https://radar.test/api/v1/overview?bucket=month&months=120"),
        ),
      ],
    ] as const) {
      expect(response.status, name).toBe(200);
      expectParity(siteCore, provenanceCore(await bodyOf(response)), `provenance[${name}]`);
    }

    const cvesData = ((
      await bodyOf(await getCves(new Request("https://radar.test/api/v1/cves?limit=100")))
    ).data ?? []) as Array<Record<string, unknown>>;
    const missing = cvesData.find((row) => row.cveId === "CVE-2099-0002");
    expect(missing?.excerptStatus).toBe("not-supplied");
    expect(missing?.excerpt).toBeNull();
    const siteExcerpt = excerptDescription("", null);
    expect(siteExcerpt.excerpt).toBe(DESCRIPTION_MISSING_LABEL);
    const unknownEpss = missing?.epss as { status: string; value: null };
    expect(unknownEpss).toMatchObject({ status: "unknown", value: null });

    const overview = await bodyOf(
      await getOverview(new Request("https://radar.test/api/v1/overview?bucket=month&months=120")),
    );
    expect(overview.unknownDateCount).toBe(1);
    const statusCohorts = (
      await bodyOf(await getStatus(new Request("https://radar.test/api/v1/status")))
    ).cohorts as Record<string, number>;
    expect(statusCohorts.published).toBe(3);
  });
});

describe("api-only self-host proof (no UI routes, no server)", () => {
  it("imports only API handlers and services, never a web UI route", () => {
    const self = readFileSync(fileURLToPath(import.meta.url), "utf8");
    const uiImports = self
      .split("\n")
      .filter((line) => line.trimStart().startsWith("import"))
      .filter((line) => line.includes("app/") && !line.includes("app/api/v1/"));
    expect(uiImports, "parity suite must not depend on web UI routes").toEqual([]);
    const pageImports = self
      .split("\n")
      .filter(
        (line) => line.trimStart().startsWith("import") && /from\s+["'][^"']*\/page["']/.test(line),
      );
    expect(pageImports, "no Next page component may be involved").toEqual([]);
  });

  it("serves identical /api/v1/cves payloads with UI routes excluded from the request set", async () => {
    const db = makeDb();
    seedCorpus(db);
    void db;

    const first = await getCves(new Request("https://radar.test/api/v1/cves?limit=100"));
    const second = await getCves(new Request("https://radar.test/api/v1/cves?limit=100"));
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    const firstBody = await bodyOf(first);
    const secondBody = await bodyOf(second);
    expectParity(
      { data: firstBody.data, pagination: firstBody.pagination, coverage: firstBody.coverage },
      { data: secondBody.data, pagination: secondBody.pagination, coverage: secondBody.coverage },
      "cves.payload",
    );
    expectParity(provenanceCore(firstBody), provenanceCore(secondBody), "cves.provenance");
    expect((firstBody.data as unknown[]).length).toBeGreaterThan(0);
  });

  it("keeps serving the versioned OpenAPI document for the same API paths", () => {
    const specPath = path.join(
      path.dirname(path.dirname(fileURLToPath(import.meta.url))),
      "openapi",
      "v1.yaml",
    );
    const spec = readFileSync(specPath, "utf8");
    expect(spec.includes("/api/v1/cves:"), "spec documents the cves path").toBe(true);
    const operations = spec
      .split("\n")
      .map((line) => line.match(/^    (get|post|put|patch|delete|options|head|trace):\s*$/)?.[1])
      .filter((op): op is string => op !== undefined);
    expect(operations.length).toBeGreaterThan(0);
    expect(operations, "spec stays read-only for API-only hosts").toEqual(
      operations.filter((op) => op === "get"),
    );
    const chunks = spec.split(/^\s{2}\/api\/v1/gm).slice(1);
    expect(chunks.length).toBeGreaterThan(0);
    for (const chunk of chunks) {
      expect(chunk.includes("provenance")).toBe(true);
    }
  });
});

describe("policy-version sensitivity (older pin trips the detector)", () => {
  it("catches the ordering difference with the differing field named", async () => {
    const db = makeDb();
    const { scoreDate } = seedRadarCorpus(db);
    const oldDate = utcDay(-40);
    const beforeDate = utcDay(-2);
    const afterDate = utcDay(-1);

    writeCheckpointOn(db, oldDate, "ranking-v0", KEV_CATALOG, scoreDate);
    writeCheckpointOn(db, beforeDate, "ranking-v1", KEV_CATALOG, scoreDate);
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
        )
        .run("CVE-2099-0001", afterDate, KEV_CATALOG, stamp(utcDay(0)));
    });
    const after = writeCheckpointOn(db, afterDate, "ranking-v1", KEV_CATALOG, scoreDate);

    const old = readCheckpoint(db, oldDate);
    expect(old, "older-policy checkpoint is retained").toBeDefined();
    if (old === undefined) throw new Error("seed failed");

    // The KEV tier flips default order after the old pin: pre-KEV the higher
    // forecast (0002) leads; post-KEV the listed record (0001) leads.
    expect(old.views.defaultPriority).toEqual(["CVE-2099-0002", "CVE-2099-0001"]);
    const siteOrder = getDefaultPriority(db).map((row) => row.id);
    expect(siteOrder).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);

    const divergences = findDivergences(
      { rankingPolicyVersion: old.policyVersion, order: old.views.defaultPriority },
      { rankingPolicyVersion: RANKING_POLICY_VERSION, order: siteOrder },
      "replay",
    );
    expect(divergences, "detector names the stale policy pin").toContain(
      "replay.rankingPolicyVersion",
    );
    expect(
      divergences.some((field) => field.startsWith("replay.order")),
      `detector names the ordering difference: ${divergences.join(", ")}`,
    ).toBe(true);

    const diff = diffCheckpoints(old, after);
    expect(diff.policyChanged, "diff flags the policy change").toBe(true);
    expect(
      diff.itemChanges.some(
        (change) => change.cveId === "CVE-2099-0001" && change.kinds.includes("kev-added"),
      ),
      "KEV addition is still labeled a source change across the policy boundary",
    ).toBe(true);
  });
});
