// Regression test (P0.1 of docs/plans/v3-wrapup.md): every read path trusted
// the aggregate cache on "a row exists". After an accepted import whose
// aggregate refresh failed, that row holds the PREVIOUS dataset's counts while
// provenance reports the NEW revision, so a response pairs fresh metadata with
// stale numbers. This seeds the cache, then accepts a newer revision without
// refreshing (the failed-refresh case) and asserts that no response pairs the
// two: status/overview/page must serve numbers matching the live tables under
// the new revision, and no ETag may seed a 304 from the stale generation.
// After a real refresh the same paths serve the cache again.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { GET as getHealth } from "../app/api/v1/health/route";
import { GET as getOverview } from "../app/api/v1/overview/route";
import { GET as getStatus } from "../app/api/v1/status/route";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/db-handle";
import { resetHardeningState } from "../app/api/v1/_lib/guardrails";
import { loadOverviewData } from "../src/components/overview/loadOverview";
import {
  aggregatesAreCurrent,
  getAggregates,
  readCurrentAggregates,
  refreshAggregates,
} from "../src/lib/aggregates";
import { type CveDatabase, openDatabase, resetReadDatabaseCache } from "../src/lib/db";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

/** Anchored to the real clock: the overview route buckets around "now". */
const NOW_ISO = new Date().toISOString();
const TODAY = NOW_ISO.slice(0, 10);
const MODEL = "v2026.06.15";
const KEV_CATALOG = "2026.10.23";
/** Two rows before the failed refresh, three after the accepted import. */
const GEN1_PUBLISHED = 2;
const GEN2_PUBLISHED = 3;

function makeDb(): { db: CveDatabase; dir: string } {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-aggregate-freshness-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return { db, dir };
}

afterEach(() => {
  resetDbOverride();
  resetHardeningState();
  resetReadDatabaseCache();
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

function insertRecord(db: CveDatabase, cveId: string, revision: string): void {
  db.handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at) " +
        "VALUES (?, '5.1', 'PUBLISHED', ?, ?, ?, ?, 'en', ?, ?, ?)",
    )
    .run(
      cveId,
      `${TODAY}T00:00:00.000Z`,
      `${TODAY}T00:00:00.000Z`,
      `Title ${cveId}`,
      `Description ${cveId}`,
      revision,
      NOW_ISO,
      NOW_ISO,
    );
}

function insertEpss(db: CveDatabase, cveId: string): void {
  db.handle
    .prepare(
      "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, '0.4', '0.9')",
    )
    .run(cveId, TODAY, MODEL);
}

function insertRun(db: CveDatabase, source: string, revision: string): void {
  db.handle
    .prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, 'succeeded', ?, 'h', NULL)",
    )
    .run(source, NOW_ISO, NOW_ISO, revision);
}

/**
 * Accepted generation 1: two published records, one KEV listing, one EPSS
 * observation each, and a snapshot computed from exactly that.
 */
function seedGenerationOne(db: CveDatabase): void {
  insertRecord(db, "CVE-2099-0001", "rev-1");
  insertRecord(db, "CVE-2099-0002", "rev-1");
  insertEpss(db, "CVE-2099-0001");
  insertEpss(db, "CVE-2099-0002");
  db.handle
    .prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    )
    .run("CVE-2099-0001", `${TODAY}T00:00:00.000Z`, KEV_CATALOG, NOW_ISO);
  insertRun(db, "cve", "rev-1");
  insertRun(db, "kev", KEV_CATALOG);
  insertRun(db, "epss", `${TODAY}@${MODEL}`);
  refreshAggregates(db, NOW_ISO);
}

/**
 * The bug's trigger: the import is accepted (ledger row + a new record) and the
 * aggregate refresh never runs. The stored snapshot is now stale, not absent.
 */
function acceptGenerationTwoWithoutRefresh(db: CveDatabase): void {
  insertRecord(db, "CVE-2099-0003", "rev-2");
  insertRun(db, "cve", "rev-2");
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function cveRevisionOf(body: Record<string, unknown>): string | null {
  const provenance = body.provenance as {
    sources: { cve: { revision: string | null } };
  };
  return provenance.sources.cve.revision;
}

describe("aggregate freshness (P0.1)", () => {
  it("serves live numbers, never the previous generation's counts, under a fresh revision", async () => {
    const { db, dir } = makeDb();
    seedGenerationOne(db);
    expect(aggregatesAreCurrent(db)).toBe(true);
    expect(getAggregates(db)?.publishedTotal).toBe(GEN1_PUBLISHED);

    acceptGenerationTwoWithoutRefresh(db);

    // The premise: a stale row exists and holds the old counts, so readers
    // that ask only "is there a row?" would serve them.
    expect(aggregatesAreCurrent(db)).toBe(false);
    expect(getAggregates(db)?.publishedTotal).toBe(GEN1_PUBLISHED);

    const status = await getStatus(new Request("http://x/api/v1/status"));
    expect(status.status).toBe(200);
    const statusBody = await bodyOf(status);
    expect(cveRevisionOf(statusBody)).toBe("rev-2");
    expect((statusBody.cohorts as { published: number }).published).toBe(GEN2_PUBLISHED);
    // No ETag: a stale generation must not seed a 304 for either dataset.
    expect(status.headers.get("ETag")).toBeNull();

    const overview = await getOverview(new Request("http://x/api/v1/overview?bucket=day&months=3"));
    expect(overview.status).toBe(200);
    const overviewBody = await bodyOf(overview);
    expect(cveRevisionOf(overviewBody)).toBe("rev-2");
    expect((overviewBody.coverage as { eligibleCohort: number }).eligibleCohort).toBe(
      GEN2_PUBLISHED,
    );
    const today = (overviewBody.buckets as Array<{ bucketStart: string; count: number }>).find(
      (bucket) => bucket.bucketStart === TODAY,
    );
    expect(today?.count).toBe(GEN2_PUBLISHED);
    expect(overview.headers.get("ETag")).toBeNull();

    const health = await getHealth(new Request("http://x/api/v1/health"));
    const healthBody = await bodyOf(health);
    expect(healthBody.status).toBe("ok");
    expect(cveRevisionOf(healthBody)).toBe("rev-2");
    expect(health.headers.get("ETag")).toBeNull();

    // The page loader reads through a read-only handle; it must take the live
    // branch too, and label the live numbers as such.
    db.close();
    openDbs.pop();
    const page = loadOverviewData(dir, NOW_ISO);
    expect(page?.publishedTotal).toBe(GEN2_PUBLISHED);
    expect(page?.corpus.published).toBe(GEN2_PUBLISHED);
    expect(page?.corpus.computedAt).toBeNull();
    expect(page?.corpus.sourceRevision).toBe("rev-2");
    expect(page?.provenance.sources.cve.revision).toBe("rev-2");
  });

  it("serves the cache again once the refresh lands, with an ETag from that generation", async () => {
    const { db, dir } = makeDb();
    seedGenerationOne(db);
    acceptGenerationTwoWithoutRefresh(db);
    refreshAggregates(db, NOW_ISO);

    expect(aggregatesAreCurrent(db)).toBe(true);
    const read = readCurrentAggregates(db);
    expect(read.current).toBe(true);
    expect(read.cached?.sourceRevision).toBe("rev-2");
    expect(read.cached?.publishedTotal).toBe(GEN2_PUBLISHED);

    // The fix must not disable revalidation: a current generation seeds an ETag
    // and still reports the numbers it was computed from.
    const status = await getStatus(new Request("http://x/api/v1/status"));
    expect(status.headers.get("ETag")).toMatch(/^"[0-9a-f]{64}"$/);
    const statusBody = await bodyOf(status);
    expect(cveRevisionOf(statusBody)).toBe("rev-2");
    expect((statusBody.cohorts as { published: number }).published).toBe(GEN2_PUBLISHED);

    db.close();
    openDbs.pop();
    const page = loadOverviewData(dir, NOW_ISO);
    expect(page?.corpus.published).toBe(GEN2_PUBLISHED);
    expect(page?.corpus.computedAt).toBe(NOW_ISO);
    expect(page?.corpus.sourceRevision).toBe("rev-2");
  });
});
