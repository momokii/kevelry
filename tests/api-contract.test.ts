import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { writeCheckpoint } from "../src/lib/radar";
import {
  resetDbOverride,
  setDbOverride,
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

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC_PATH = join(ROOT, "openapi", "v1.yaml");
const DOCS_DIR = join(ROOT, "docs", "api");

function readSpec(): string {
  return readFileSync(SPEC_PATH, "utf8");
}

function readDocs(): Map<string, string> {
  const files = readdirSync(DOCS_DIR).filter((name) => name.endsWith(".md")).sort();
  const pages = new Map<string, string>();
  for (const name of files) {
    pages.set(name, readFileSync(join(DOCS_DIR, name), "utf8"));
  }
  expect(pages.size).toBeGreaterThan(0);
  return pages;
}

/** `  /api/v1/...:` lines are path items (4-space indent marks operations). */
function specPaths(spec: string): string[] {
  return spec
    .split("\n")
    .map((line) => line.match(/^  (\/api\/v1[^:]*):\s*$/)?.[1])
    .filter((path): path is string => path !== undefined);
}

/** Lines shaped like `GET /api/v1/...` declare a documented endpoint. */
function documentedEndpoints(pages: Map<string, string>): { page: string; endpoint: string }[] {
  const found: { page: string; endpoint: string }[] = [];
  for (const [page, text] of pages) {
    for (const line of text.split("\n")) {
      const match = line.match(/^\s*GET\s+(\/api\/v1[^\s`?]*)/);
      if (match?.[1]) {
        found.push({ page, endpoint: match[1] });
      }
    }
  }
  return found;
}

function templateMatches(template: string, concrete: string): boolean {
  const pattern = new RegExp(
    `^${template.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\{[^/]+\\\}/g, "[^/]+")}$`,
  );
  return pattern.test(concrete.split("?")[0] ?? "");
}

describe("api contract completeness", () => {
  it("documents every spec path and every documented endpoint exists in the spec", () => {
    const templates = specPaths(readSpec());
    expect(templates.length).toBeGreaterThan(0);

    const documented = documentedEndpoints(readDocs());
    expect(documented.length).toBeGreaterThan(0);

    const missing = documented.filter(
      ({ endpoint }) => !templates.some((template) => templateMatches(template, endpoint)),
    );
    expect(
      missing.map(({ page, endpoint }) => `${page}: ${endpoint}`),
      "documented endpoints missing from openapi/v1.yaml",
    ).toEqual([]);

    const undocumented = templates.filter((template) =>
      documented.every(({ endpoint }) => !templateMatches(template, endpoint)),
    );
    expect(undocumented, "spec paths with no docs/api page").toEqual([]);
  });

  it("stays read-only: no write operations in the spec, none documented", () => {
    const spec = readSpec();
    const operations = spec
      .split("\n")
      .map((line) => line.match(/^    (get|post|put|patch|delete|options|head|trace):\s*$/)?.[1])
      .filter((op): op is string => op !== undefined);
    expect(operations.length).toBeGreaterThan(0);
    expect(operations, "spec must expose GET routes only").toEqual(
      operations.filter((op) => op === "get"),
    );

    for (const [page, text] of readDocs()) {
      for (const line of text.split("\n")) {
        expect(
          line.match(/^\s*(POST|PUT|PATCH|DELETE)\s+\/api\/v1/),
          `${page} must not document write endpoints`,
        ).toBeNull();
      }
    }
  });

  it("carries provenance in every path block", () => {
    const chunks = readSpec().split(/^\s{2}\/api\/v1/gm).slice(1);
    expect(chunks.length).toBeGreaterThan(0);
    for (const chunk of chunks) {
      expect(chunk.includes("provenance")).toBe(true);
    }
  });

  it("represents unknown EPSS as explicit null, never 0", () => {
    const spec = readSpec();
    expect(spec.match(/status: unknown\s*\n\s*value: null/), "unknown EPSS example").not.toBeNull();
    expect(spec.match(/status: known\s*\n\s*value: 0\b/), "known-zero EPSS example").not.toBeNull();
    const unknownBlocks = spec.match(/status: unknown\s*\n\s*value: [^\n]*/g) ?? [];
    expect(unknownBlocks.length).toBeGreaterThan(0);
    for (const block of unknownBlocks) {
      expect(block.endsWith("value: null")).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Docs-example replay (plan todo 15): every human-docs curl example replays
// against the running handlers in-process (no live server) and returns the
// documented shapes. Fixture IDs are invented CVE-2099 values; the docs use
// illustrative CVE-2026 IDs, so replay uses fixture equivalents with the same
// path template and query structure. Removing any endpoint from docs/api must
// fail the completeness test above; replaying a removed endpoint's docs URL
// structure here would then also lose its shape assertion.
// ---------------------------------------------------------------------------

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const SCORE_DATE = "2026-10-23";
const PREV_DATE = "2026-10-16";
const LONG_DESC = `A denial of service flaw was found in the packet parser when handling fragmented datagrams with overlapping offsets. A remote attacker can trigger unbounded memory growth and worker starvation by sending a crafted sequence of overlapping fragments over several minutes, leading to sustained CPU pressure, dropped legitimate traffic, additional memory allocator churn, repeated reassembly timeouts, and eventual process termination across affected builds. ${"Padding text to push this description past the excerpt limit. ".repeat(6)}`;

function makeDocsDb(): CveDatabase {
  const dir = mkdtempSync(join(tmpdir(), "cve-docs-replay-test-"));
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

function seedDocsSyncRuns(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    const insert = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insert.run("cve", "2026-10-24T03:50:00.000Z", "2026-10-24T03:55:00.000Z", "succeeded", "rev-test-aaa", "hash-cve", null);
    insert.run("kev", "2026-10-24T03:50:00.000Z", "2026-10-24T03:55:00.000Z", "succeeded", "2026.10.23", "hash-kev", null);
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

function seedDocsRecord(
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
        null,
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

/** Same signal mix as the route suite: known, unknown, legacy, zero, adp-only. */
function seedDocsCorpus(db: CveDatabase): void {
  seedDocsRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
    description: LONG_DESC,
    published: "2026-10-20T14:02:00.000Z",
    metrics: [{ origin: "CNA", version: "4.0", baseScore: "9.2", vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }],
    kev: "2026-10-23",
    epss: [{ date: SCORE_DATE, value: "0.1162", percentile: "0.96047" }],
  });
  seedDocsRecord(db, "CVE-2099-0002", {
    description: "",
    lang: null,
    published: "2026-10-19T09:30:00.000Z",
  });
  seedDocsRecord(db, "CVE-2099-0003", {
    published: "2026-10-18T07:45:00.000Z",
    metrics: [{ origin: "CNA", version: "2.0", baseScore: "10.0", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C" }],
    epss: [{ date: SCORE_DATE, value: "0", percentile: "0.08100" }],
  });
  seedDocsRecord(db, "CVE-2099-0005", {
    published: null,
    metrics: [{ origin: "ADP", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
  });
  seedDocsRecord(db, "CVE-2099-0006", {
    published: "2026-10-17T10:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "7.5", vector: "CVSS:3.1/AV:N" }],
    epss: [
      { date: PREV_DATE, value: "0.10", percentile: "0.90000" },
      { date: SCORE_DATE, value: "0.18", percentile: "0.97500" },
    ],
  });
  seedDocsSyncRuns(db);
}

function seedDocsRadar(db: CveDatabase): void {
  seedDocsRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
    description: "A heap overflow in the parser allows remote code execution",
    published: "2026-10-20T00:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" }],
    epss: [{ date: SCORE_DATE, value: "0.1162", percentile: "0.96047" }],
  });
  seedDocsRecord(db, "CVE-2099-0002", {
    description: "A use-after-free in the renderer with moderate impact",
    published: "2026-10-19T00:00:00.000Z",
    metrics: [{ origin: "CNA", version: "3.1", baseScore: "5.4", vector: "CVSS:3.1/AV:L" }],
  });
  seedDocsSyncRuns(db);
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

async function docsBody(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function expectDocsRateHeaders(response: Response): void {
  expect(response.headers.get("x-ratelimit-limit"), "X-RateLimit-Limit on docs replay").toBe("600");
  expect(Number(response.headers.get("x-ratelimit-remaining"))).toBeGreaterThanOrEqual(0);
  expect(Number(response.headers.get("x-ratelimit-reset"))).toBeGreaterThanOrEqual(0);
}

function expectDocsProvenance(body: Record<string, unknown>): void {
  const provenance = body.provenance as Record<string, unknown>;
  expect(provenance.rankingPolicyVersion, "docs replay carries ranking-v1").toBe("ranking-v1");
  expect(typeof provenance.generatedAt).toBe("string");
  const sources = provenance.sources as Record<string, Record<string, unknown>>;
  expect(sources.cve?.revision).toBe("rev-test-aaa");
  expect(sources.kev?.catalogVersion).toBe("2026.10.23");
  expect(sources.epss?.scoreDate).toBe(SCORE_DATE);
  expect(sources.epss?.modelVersion).toBe(MODEL);
}

function expectPaginationShape(body: Record<string, unknown>, limit: number): void {
  const pagination = body.pagination as { limit: number; hasMore: boolean; nextCursor: string | null };
  expect(pagination.limit).toBe(limit);
  expect(typeof pagination.hasMore).toBe("boolean");
  expect(pagination.nextCursor === null || typeof pagination.nextCursor === "string").toBe(true);
}

function expectCoverageShape(body: Record<string, unknown>): void {
  const coverage = body.coverage as Record<string, number>;
  for (const key of ["eligibleCohort", "returned", "unscored", "unknownEpss", "unknownDate"]) {
    expect(typeof coverage[key], `coverage.${key} is a number`).toBe("number");
  }
}

function expectCveItemShape(row: Record<string, unknown>): void {
  expect(typeof row.cveId).toBe("string");
  expect(row.officialUrl).toBe(`https://www.cve.org/CVERecord?id=${row.cveId as string}`);
  expect(typeof row.excerptStatus).toBe("string");
  const epss = row.epss as { status: string; value: number | null };
  expect(["known", "unknown"]).toContain(epss.status);
  if (epss.status === "unknown") {
    expect(epss.value).toBeNull();
  } else {
    expect(typeof epss.value).toBe("number");
  }
  expect(typeof (row.provenance ?? null) === "object" || row.provenance === undefined).toBe(true);
}

/** curl "..." URLs embedded in docs/api pages (example origin, replayed in-process). */
function docsCurlUrls(): { page: string; url: string }[] {
  const found: { page: string; url: string }[] = [];
  for (const [page, text] of readDocs()) {
    for (const line of text.split("\n")) {
      const match = line.match(/curl\s+"([^"]+)"/);
      if (match?.[1]) {
        found.push({ page, url: match[1] });
      }
    }
  }
  return found;
}

describe("docs examples replay against live handlers", () => {
  it("replays fixture equivalents of every documented curl example with documented shapes", async () => {
    const db = makeDocsDb();
    seedDocsCorpus(db);
    void db;

    // Mirrors docs/api curl examples with fixture IDs (docs use illustrative
    // CVE-2026 IDs; the path template and query structure are identical).
    const list = await getCves(new Request("https://radar.test/api/v1/cves?limit=2&kev=listed"));
    expect(list.status).toBe(200);
    expectDocsRateHeaders(list);
    const listBody = await docsBody(list);
    expectDocsProvenance(listBody);
    expectPaginationShape(listBody, 2);
    expectCoverageShape(listBody);
    const listData = listBody.data as Array<Record<string, unknown>>;
    expect(listData.map((row) => row.cveId)).toEqual(["CVE-2099-0001"]);
    for (const row of listData) expectCveItemShape(row);

    const detail = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0001"), {
      params: Promise.resolve({ cveId: "CVE-2099-0001" }),
    });
    expect(detail.status).toBe(200);
    expectDocsRateHeaders(detail);
    const detailBody = await docsBody(detail);
    expectDocsProvenance(detailBody);
    expectCveItemShape(detailBody.data as Record<string, unknown>);

    const search = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser&limit=2"),
    );
    expect(search.status).toBe(200);
    expectDocsRateHeaders(search);
    const searchBody = await docsBody(search);
    expectDocsProvenance(searchBody);
    expectPaginationShape(searchBody, 2);
    expectCoverageShape(searchBody);
    expect(searchBody.q).toBe("packet parser");
    const searchData = searchBody.data as Array<Record<string, unknown>>;
    expect(searchData.length).toBeGreaterThan(0);
    for (const row of searchData) expectCveItemShape(row);

    const exploited = await getPriority(
      new Request("https://radar.test/api/v1/priority/known-exploited?limit=2"),
      { params: Promise.resolve({ listName: "known-exploited" }) },
    );
    expect(exploited.status).toBe(200);
    expectDocsRateHeaders(exploited);
    const exploitedBody = await docsBody(exploited);
    expectDocsProvenance(exploitedBody);
    expectPaginationShape(exploitedBody, 2);
    expectCoverageShape(exploitedBody);
    expect(exploitedBody.list).toBe("known-exploited");
    expect(exploitedBody.ordering).toEqual(["kev-dateAdded-desc", "cveId-asc"]);
    expect(exploitedBody.deltaPp).toBeNull();

    const rising = await getPriority(
      new Request("https://radar.test/api/v1/priority/rising-forecast?limit=2"),
      { params: Promise.resolve({ listName: "rising-forecast" }) },
    );
    expect(rising.status).toBe(200);
    const risingBody = await docsBody(rising);
    expectDocsProvenance(risingBody);
    expect(risingBody.deltaPp).toEqual([8]);

    const overview = await getOverview(
      new Request("https://radar.test/api/v1/overview?bucket=month&months=2"),
    );
    expect(overview.status).toBe(200);
    expectDocsRateHeaders(overview);
    const overviewBody = await docsBody(overview);
    expectDocsProvenance(overviewBody);
    expect(overviewBody.bucket).toBe("month");
    expect(overviewBody.dateBasis).toBe("publishedAt-utc");
    expect(typeof overviewBody.unknownDateCount).toBe("number");
    expectCoverageShape(overviewBody);

    const status = await getStatus(new Request("https://radar.test/api/v1/status"));
    expect(status.status).toBe(200);
    expectDocsRateHeaders(status);
    const statusBody = await docsBody(status);
    expect(statusBody.rankingPolicyVersion).toBe("ranking-v1");
    expect(Array.isArray(statusBody.notices)).toBe(true);
    expect((statusBody.notices as string[]).length).toBeGreaterThanOrEqual(3);
    expectDocsProvenance(statusBody);

    const health = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(health.status).toBe(200);
    expectDocsRateHeaders(health);
    const healthBody = await docsBody(health);
    expect(healthBody.status).toBe("ok");
    expect(healthBody.version).toBe("v1");
    expectDocsProvenance(healthBody);
  });

  it("replays radar and replay docs examples including the unavailable shape", async () => {
    const db = makeDocsDb();
    seedDocsRadar(db);
    void db;

    const radar = await getRadar(
      new Request("https://radar.test/api/v1/radar?kind=kev-added&limit=2"),
    );
    expect(radar.status).toBe(200);
    expectDocsRateHeaders(radar);
    const radarBody = await docsBody(radar);
    expectDocsProvenance(radarBody);
    expectPaginationShape(radarBody, 2);
    const events = radarBody.data as Array<Record<string, unknown>>;
    expect(events.length).toBeGreaterThan(0);
    const kevAdded = events.find((event) => event.kind === "kev-added");
    expect(kevAdded, "docs kev-added example replays").toBeDefined();
    expect(Array.isArray(kevAdded?.changes)).toBe(true);
    for (const event of events) {
      expect(typeof event.eventId).toBe("string");
      expect(typeof event.checkpointDate).toBe("string");
      expect(typeof event.observedAt).toBe("string");
      expect(typeof event.kind).toBe("string");
    }

    const checkpoints = await getCheckpoints(
      new Request("https://radar.test/api/v1/replay/checkpoints?limit=5"),
    );
    expect(checkpoints.status).toBe(200);
    expectDocsRateHeaders(checkpoints);
    const checkpointsBody = await docsBody(checkpoints);
    expectDocsProvenance(checkpointsBody);
    expectPaginationShape(checkpointsBody, 5);
    expect(typeof checkpointsBody.retainedFrom).toBe("string");
    expect(typeof checkpointsBody.retainedTo).toBe("string");

    const replayed = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-10-23&view=highest-forecast&limit=2"),
    );
    expect(replayed.status).toBe(200);
    expectDocsRateHeaders(replayed);
    const replayedBody = await docsBody(replayed);
    expectDocsProvenance(replayedBody);
    expectPaginationShape(replayedBody, 2);
    expectCoverageShape(replayedBody);
    expect(replayedBody.checkpointDate).toBe("2026-10-23");
    expect(replayedBody.rankingPolicyVersion).toBe("ranking-v1");

    const expired = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-08-01&view=highest-forecast"),
    );
    expect(expired.status).toBe(404);
    const expiredBody = await docsBody(expired);
    expect(expiredBody.code).toBe("REPLAY_UNAVAILABLE");
    expect((expiredBody.details as { reason: string }).reason).toBe("expired");
  });

  it("keeps unknown EPSS explicit null and known zero distinct in live detail responses", async () => {
    const db = makeDocsDb();
    seedDocsCorpus(db);
    void db;

    const unknown = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0002"), {
      params: Promise.resolve({ cveId: "CVE-2099-0002" }),
    });
    expect(unknown.status).toBe(200);
    const unknownEpss = ((await docsBody(unknown)).data as Record<string, unknown>).epss as {
      status: string;
      value: number | null;
    };
    expect(unknownEpss.status).toBe("unknown");
    expect(unknownEpss.value).toBeNull();

    const zero = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0003"), {
      params: Promise.resolve({ cveId: "CVE-2099-0003" }),
    });
    expect(zero.status).toBe(200);
    const zeroEpss = ((await docsBody(zero)).data as Record<string, unknown>).epss as {
      status: string;
      value: number | null;
    };
    expect(zeroEpss.status).toBe("known");
    expect(zeroEpss.value).toBe(0);
  });

  it("returns documented error shapes for bad limit, bad query, unknown list, and missing replay", async () => {
    const db = makeDocsDb();
    seedDocsCorpus(db);
    void db;

    const badLimit = await getCves(new Request("https://radar.test/api/v1/cves?limit=500"));
    expect(badLimit.status).toBe(400);
    expectDocsRateHeaders(badLimit);
    const badLimitBody = await docsBody(badLimit);
    expect(badLimitBody.code).toBe("BAD_LIMIT");
    expect(typeof badLimitBody.message).toBe("string");
    expectDocsProvenance(badLimitBody);

    const badQuery = await getSearch(new Request("https://radar.test/api/v1/search?q=x"));
    expect(badQuery.status).toBe(400);
    expect((await docsBody(badQuery)).code).toBe("BAD_QUERY");

    const unknownList = await getPriority(
      new Request("https://radar.test/api/v1/priority/most-discussed"),
      { params: Promise.resolve({ listName: "most-discussed" }) },
    );
    expect(unknownList.status).toBe(404);
    expect((await docsBody(unknownList)).code).toBe("LIST_NOT_FOUND");

    const missingReplay = await getReplay(
      new Request("https://radar.test/api/v1/replay?date=2026-10-21&view=highest-forecast"),
    );
    expect(missingReplay.status).toBe(404);
    const missingBody = await docsBody(missingReplay);
    expect(missingBody.code).toBe("REPLAY_UNAVAILABLE");
    expect(typeof (missingBody.details as { reason: string }).reason).toBe("string");
  });

  it("keeps every docs curl example mapped to a spec path with its required params", async () => {
    const templates = specPaths(readSpec());
    const curls = docsCurlUrls();
    expect(curls.length).toBeGreaterThanOrEqual(10);

    for (const { page, url } of curls) {
      const parsed = new URL(url);
      const concrete = `${parsed.pathname}${parsed.search}`;
      expect(
        templates.some((template) => templateMatches(template, parsed.pathname)),
        `${page}: ${concrete} must map to a spec path`,
      ).toBe(true);
    }

    const paths = curls.map(({ url }) => new URL(url).pathname);
    for (const template of templates) {
      expect(
        paths.some((pathname) => templateMatches(template, pathname)),
        `spec path ${template} must have a replayable docs curl example`,
      ).toBe(true);
    }

    const searchCurl = curls.find(({ url }) => new URL(url).pathname === "/api/v1/search");
    expect(searchCurl, "search docs must include a curl example with q").toBeDefined();
    expect(new URL(searchCurl?.url ?? "").searchParams.get("q")).not.toBeNull();

    const replayCurl = curls.find(({ url }) => new URL(url).pathname === "/api/v1/replay");
    expect(replayCurl, "replay docs must include a curl example with date and view").toBeDefined();
    const replayParams = new URL(replayCurl?.url ?? "").searchParams;
    expect(replayParams.get("date")).toMatch(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/);
    expect(replayParams.get("view")).not.toBeNull();
  });
});
