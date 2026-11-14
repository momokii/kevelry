// New-test justification (v3 epic E4): the bulk route is a second way to read
// the same accepted snapshots the single-record route serves, so it must be
// proven against the real handler (not a shape fixture) that a bulk item is
// byte-identical to the detail item for the same record, that requested order
// survives dedupe, that absent or non-public ids are reported in
// `resolution.missingIds` instead of failing the whole request or being
// fabricated, that the 50-id cap and conflicting-parameter rejections are
// enforced with rate-limit headers, and that the ETag is seeded over the
// canonical sorted id set so the same set revalidates as 304. Fixture IDs are
// invented CVE-2099 values; nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { refreshAggregates } from "../src/lib/aggregates";
import { type CveDatabase, openDatabase } from "../src/lib/db";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/db-handle";
import { resetHardeningState } from "../app/api/v1/_lib/guardrails";
import { GET as getBatch, OPTIONS as optionsBatch } from "../app/api/v1/cves/batch/route";
import { GET as getCveById } from "../app/api/v1/cves/[cveId]/route";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-10-24T00:00:00.000Z";
const MODEL = "v2026.06.15";
const SCORE_DATE = "2026-10-23";
const BASE = "https://radar.test/api/v1/cves/batch";

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-api-batch-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return db;
}

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

function seedRecord(
  db: CveDatabase,
  cveId: string,
  opts: {
    title?: string | null;
    description?: string;
    state?: string;
    published?: string | null;
    metrics?: Array<{ origin: string; version: string; baseScore: string; vector?: string }>;
    kev?: string | null;
    epss?: Array<{ date: string; value: string; percentile?: string }>;
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
        "en",
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
        .run(cveId, row.date, MODEL, row.value, row.percentile ?? "0.90000");
    }
  });
}

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

/** Four PUBLISHED records plus one REJECTED record that must not be served. */
function seedCorpus(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0001", {
    title: "CVE-2099-0001",
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
  seedRecord(db, "CVE-2099-0002", { published: "2026-10-19T09:30:00.000Z" });
  seedRecord(db, "CVE-2099-0003", {
    published: "2026-10-18T07:45:00.000Z",
    metrics: [
      { origin: "ADP", version: "3.1", baseScore: "9.8", vector: "CVSS:3.1/AV:N" },
      { origin: "CNA", version: "3.1", baseScore: "7.5", vector: "CVSS:3.1/AV:N" },
    ],
  });
  seedRecord(db, "CVE-2099-0004", {
    published: null,
    metrics: [
      { origin: "CNA", version: "2.0", baseScore: "10.0", vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C" },
    ],
    epss: [{ date: SCORE_DATE, value: "0", percentile: "0.08100" }],
  });
  seedRecord(db, "CVE-2099-0009", { state: "REJECTED" });
  seedSyncRuns(db);
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function expectRateHeaders(response: Response): void {
  expect(response.headers.get("X-RateLimit-Limit")).toBe("600");
  expect(Number(response.headers.get("X-RateLimit-Remaining"))).toBeGreaterThanOrEqual(0);
  expect(Number(response.headers.get("X-RateLimit-Reset"))).toBeGreaterThanOrEqual(0);
}

function idsOf(body: Record<string, unknown>): string[] {
  return (body.data as Array<{ cveId: string }>).map((item) => item.cveId);
}

describe("bulk CVE lookup route", () => {
  it("returns an item deep-equal to the single-record route for the same id", async () => {
    const db = makeDb();
    seedCorpus(db);

    const batch = await getBatch(new Request(`${BASE}?ids=CVE-2099-0001`));
    expect(batch.status).toBe(200);
    expectRateHeaders(batch);
    const batchBody = await bodyOf(batch);

    const detail = await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0001"), {
      params: Promise.resolve({ cveId: "CVE-2099-0001" }),
    });
    expect(detail.status).toBe(200);
    const detailItem = (await bodyOf(detail)).data as Record<string, unknown>;
    // Detail adds the per-record extras; every field bulk serves must match.
    const parityItem = { ...detailItem };
    delete parityItem.descriptionLanguages;
    delete parityItem.references;
    delete parityItem.epssHistory;

    const batchItem = (batchBody.data as Array<Record<string, unknown>>)[0];
    expect(batchItem).toEqual(parityItem);
    expect(batchBody.resolution).toEqual({
      requested: 1,
      returned: 1,
      missingIds: [],
    });
    expect(batchBody).not.toHaveProperty("pagination");
    expect(batchBody).not.toHaveProperty("coverage");
    const provenance = batchBody.provenance as Record<string, unknown>;
    expect(provenance.rankingPolicyVersion).toBe("ranking-v1");
    const sources = provenance.sources as Record<string, Record<string, unknown>>;
    expect(sources.cve?.revision).toBe("rev-test-aaa");
    expect(sources.epss?.scoreDate).toBe(SCORE_DATE);
  });

  it("preserves requested order and dedupes without reordering", async () => {
    const db = makeDb();
    seedCorpus(db);

    const shuffled = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0004,CVE-2099-0001,CVE-2099-0003`),
    );
    expect(shuffled.status).toBe(200);
    const shuffledBody = await bodyOf(shuffled);
    expect(idsOf(shuffledBody)).toEqual(["CVE-2099-0004", "CVE-2099-0001", "CVE-2099-0003"]);

    // Whitespace is trimmed, empty elements dropped, first-seen order kept.
    const duplicated = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0003, ,CVE-2099-0001,CVE-2099-0003,CVE-2099-0001`),
    );
    expect(duplicated.status).toBe(200);
    const duplicatedBody = await bodyOf(duplicated);
    expect(idsOf(duplicatedBody)).toEqual(["CVE-2099-0003", "CVE-2099-0001"]);
    expect(duplicatedBody.resolution).toEqual({ requested: 2, returned: 2, missingIds: [] });
  });

  it("reports absent and non-public ids in resolution.missingIds without failing", async () => {
    const db = makeDb();
    seedCorpus(db);

    const response = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0001,CVE-2099-9999,CVE-2099-0009,CVE-2099-0002`),
    );
    expect(response.status).toBe(200);
    expectRateHeaders(response);
    const body = await bodyOf(response);
    expect(idsOf(body)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
    expect(body.resolution).toEqual({
      requested: 4,
      returned: 2,
      missingIds: ["CVE-2099-9999", "CVE-2099-0009"],
    });

    // An all-missing request is still a 200 with an empty data array.
    const empty = await getBatch(new Request(`${BASE}?ids=CVE-2099-9999`));
    expect(empty.status).toBe(200);
    const emptyBody = await bodyOf(empty);
    expect(emptyBody.data).toEqual([]);
    expect(emptyBody.resolution).toEqual({
      requested: 1,
      returned: 0,
      missingIds: ["CVE-2099-9999"],
    });
  });

  it("accepts 50 unique ids and rejects 51 naming the cap", async () => {
    const db = makeDb();
    seedCorpus(db);

    const atCap = Array.from({ length: 50 }, (_, index) => `CVE-2099-${1000 + index}`).join(",");
    const accepted = await getBatch(new Request(`${BASE}?ids=${atCap}`));
    expect(accepted.status).toBe(200);
    const acceptedBody = await bodyOf(accepted);
    expect((acceptedBody.resolution as { requested: number }).requested).toBe(50);

    const overCap = Array.from({ length: 51 }, (_, index) => `CVE-2099-${1000 + index}`).join(",");
    const rejected = await getBatch(new Request(`${BASE}?ids=${overCap}`));
    expect(rejected.status).toBe(400);
    expectRateHeaders(rejected);
    const rejectedBody = await bodyOf(rejected);
    expect(rejectedBody.code).toBe("BAD_REQUEST");
    expect(rejectedBody.message).toContain("at most 50 unique CVE IDs");
    expect(rejectedBody.message).toContain("received 51");

    // Duplicates do not count against the cap: 51 elements, 50 unique ids.
    const withDuplicate = `${atCap},CVE-2099-1000`;
    const deduped = await getBatch(new Request(`${BASE}?ids=${withDuplicate}`));
    expect(deduped.status).toBe(200);
  });

  it("rejects an invalid id shape, a missing ids param, and repeated ids", async () => {
    const db = makeDb();
    seedCorpus(db);

    const invalid = await getBatch(new Request(`${BASE}?ids=CVE-2099-0001,not-a-cve`));
    expect(invalid.status).toBe(400);
    expectRateHeaders(invalid);
    expect((await bodyOf(invalid)).code).toBe("BAD_ID");

    const missing = await getBatch(new Request(BASE));
    expect(missing.status).toBe(400);
    expect((await bodyOf(missing)).code).toBe("BAD_REQUEST");
    expect((await bodyOf(await getBatch(new Request(BASE)))).message).toContain("ids is required");

    const blank = await getBatch(new Request(`${BASE}?ids=`));
    expect(blank.status).toBe(400);
    expect((await bodyOf(blank)).message).toContain("at least one CVE ID");

    const repeated = await getBatch(new Request(`${BASE}?ids=CVE-2099-0001&ids=CVE-2099-0002`));
    expect(repeated.status).toBe(400);
    expect((await bodyOf(repeated)).message).toContain("ids must be supplied once");
  });

  it("rejects every known conflicting param by name and ignores unknown ones", async () => {
    const db = makeDb();
    seedCorpus(db);

    const conflicting: Record<string, string> = {
      cursor: "MA==",
      limit: "5",
      severity: "critical",
      kev: "listed",
      epss: "scored",
      exploit: "tagged",
      publishedStart: "2026-10-01T00:00:00Z",
      publishedEnd: "2026-10-25T00:00:00Z",
      vendor: "microsoft",
      q: "openssl",
    };
    for (const [name, value] of Object.entries(conflicting)) {
      const params = new URLSearchParams({ ids: "CVE-2099-0001", [name]: value });
      const response = await getBatch(new Request(`${BASE}?${params.toString()}`));
      expect(response.status, `${name} rejected`).toBe(400);
      expectRateHeaders(response);
      const body = await bodyOf(response);
      expect(body.code, `${name} code`).toBe("BAD_REQUEST");
      expect(String(body.message), `${name} named in message`).toContain(name);
    }

    // Unknown params are ignored, not rejected: no documented meaning exists
    // to conflict with, so the documented ids-only contract still holds.
    const ignored = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0001&utm_source=docs&trace=1`),
    );
    expect(ignored.status).toBe(200);
    expect(idsOf(await bodyOf(ignored))).toEqual(["CVE-2099-0001"]);
  });

  it("revalidates 304 from an ETag seeded over the canonical sorted id set", async () => {
    const db = makeDb();
    seedCorpus(db);
    refreshAggregates(db);

    const first = await getBatch(new Request(`${BASE}?ids=CVE-2099-0003,CVE-2099-0001`));
    expect(first.status).toBe(200);
    const etag = first.headers.get("ETag");
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
    expect(first.headers.get("Cache-Control")).toBe(
      "public, max-age=30, s-maxage=60, stale-while-revalidate=300",
    );

    // Same set, different order and a duplicate: same canonical seed, so 304.
    const repeat = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0001,CVE-2099-0003,CVE-2099-0001`, {
        headers: { "If-None-Match": etag as string },
      }),
    );
    expect(repeat.status).toBe(304);
    expect(repeat.headers.get("ETag")).toBe(etag);
    expect(repeat.headers.get("X-RateLimit-Limit")).toBe("600");

    // A different set must not revalidate against the other set's ETag.
    const different = await getBatch(
      new Request(`${BASE}?ids=CVE-2099-0001`, {
        headers: { "If-None-Match": etag as string },
      }),
    );
    expect(different.status).toBe(200);
    expect(different.headers.get("ETag")).not.toBe(etag);
  });

  it("serves OPTIONS preflight and keeps error responses uncacheable", async () => {
    const db = makeDb();
    seedCorpus(db);

    const preflight = await optionsBatch(
      new Request(BASE, { method: "OPTIONS", headers: { Origin: "https://radar.test" } }),
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get("X-Content-Type-Options")).toBe("nosniff");

    const bad = await getBatch(new Request(`${BASE}?ids=not-a-cve`));
    expect(bad.status).toBe(400);
    expect(bad.headers.get("ETag")).toBeNull();
    expect(bad.headers.get("Cache-Control")).toBeNull();
  });
});
