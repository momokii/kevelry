// New-test justification (v3 epic E5): the RSS feed is a second serialization
// of the same accepted checkpoints GET /api/v1/radar serves, so it must be
// proven against the real handler that the XML document is well formed, that
// items are factual (event id, title, canonical record link, observedAt,
// before/after fields, reason, source revision), that `since`/`kind`/`cveId`
// narrow exactly like the JSON route, that `limit` caps the item count, that a
// `since` older than the checkpoint retention window is an explicit 400 naming
// the earliest allowed date instead of a silent empty feed, that `&`/`<`/`>`
// are escaped, that the content type is RSS, and that a repeat request with
// If-None-Match revalidates as 304. Fixture IDs are invented CVE-2099 values;
// nothing here touches the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { writeCheckpoint } from "../src/lib/radar";
import {
  buildRadarFeed,
  earliestAllowedCheckpointDate,
  type RadarFeedEvent,
} from "../src/lib/radar-feed";
import { resetDbOverride, setDbOverride } from "../app/api/v1/_lib/db-handle";
import { resetHardeningState } from "../app/api/v1/_lib/guardrails";
import { GET as getFeed, OPTIONS as optionsFeed } from "../app/api/v1/radar/feed.xml/route";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const STAMP = "2026-11-14T00:00:00.000Z";
const MODEL = "v2026.06.15";
const SCORE_DATE = "2026-11-14";
const BASE = "https://radar.test/api/v1/radar/feed.xml";

function utcDay(offsetDays: number): string {
  const now = new Date();
  const dayStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return new Date(dayStart + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

const D0 = utcDay(-3);
const D1 = utcDay(-2);
const D2 = utcDay(-1);
const D3 = utcDay(0);

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-radar-feed-test-"));
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

function seedRecord(db: CveDatabase, cveId: string, published: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        cveId,
        "5.1",
        "PUBLISHED",
        published,
        `Title for ${cveId}`,
        `Description for ${cveId}`,
        "en",
        "rev-feed-aaa",
        null,
        STAMP,
        STAMP,
      );
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(cveId, "CNA", "3.1", "9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0);
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run(cveId, SCORE_DATE, MODEL, "0.1162", "0.96047");
  });
}

function addKev(db: CveDatabase, cveId: string, dateAdded: string): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
      )
      .run(cveId, dateAdded, dateAdded.replace(/-/g, "."), STAMP);
  });
}

/** Two KEV additions on consecutive checkpoints, then one unchanged capture. */
function seedRadarFeed(db: CveDatabase): void {
  seedRecord(db, "CVE-2099-0001", "2026-10-20T00:00:00.000Z");
  seedRecord(db, "CVE-2099-0002", "2026-10-19T00:00:00.000Z");
  db.runBoundedWrite(() => {
    const insert = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insert.run(
      "cve",
      "2026-11-14T03:50:00.000Z",
      "2026-11-14T03:55:00.000Z",
      "succeeded",
      "rev-feed-aaa",
      "hash-cve",
      null,
    );
    insert.run(
      "kev",
      "2026-11-14T03:50:00.000Z",
      "2026-11-14T03:55:00.000Z",
      "succeeded",
      "2026.11.14",
      "hash-kev",
      null,
    );
    insert.run(
      "epss",
      "2026-11-14T03:50:00.000Z",
      "2026-11-14T03:55:00.000Z",
      "succeeded",
      `${SCORE_DATE}@${MODEL}`,
      "hash-epss",
      null,
    );
  });

  const pins = {
    cveRevision: "rev-feed-aaa",
    kevCatalogDate: D0,
    epssScoreDate: SCORE_DATE,
    epssModelVersion: MODEL,
  };
  writeCheckpoint(db, {
    checkpointDate: D0,
    observedAt: `${D0}T04:00:00.000Z`,
    sourcePins: pins,
    policyVersion: "ranking-v1",
    topN: 10,
  });
  addKev(db, "CVE-2099-0001", D1);
  writeCheckpoint(db, {
    checkpointDate: D1,
    observedAt: `${D1}T04:00:00.000Z`,
    sourcePins: { ...pins, kevCatalogDate: D1 },
    policyVersion: "ranking-v1",
    topN: 10,
  });
  addKev(db, "CVE-2099-0002", D2);
  writeCheckpoint(db, {
    checkpointDate: D2,
    observedAt: `${D2}T04:00:00.000Z`,
    sourcePins: { ...pins, kevCatalogDate: D2 },
    policyVersion: "ranking-v1",
    topN: 10,
  });
  writeCheckpoint(db, {
    checkpointDate: D3,
    observedAt: `${D3}T04:00:00.000Z`,
    sourcePins: { ...pins, kevCatalogDate: D2 },
    policyVersion: "ranking-v1",
    topN: 10,
  });
}

const TAG_RE = /<(\/?)([A-Za-z][\w:.-]*)((?:\s+[\w:.-]+="[^"<]*")*)\s*(\/?)>/g;
const ENTITY_RE = /^&(amp|lt|gt|quot|apos|#[0-9]+);$/;

/**
 * Minimal structural check with no XML dependency: every `<` opens or closes a
 * balanced tag, text carries no raw markup characters, and every `&` introduces
 * a known entity.
 */
function assertWellFormed(xml: string): void {
  expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
  const body = xml.replace(/^<\?xml[^?]*\?>\s*/, "");
  const stack: string[] = [];
  let lastIndex = 0;
  for (let match = TAG_RE.exec(body); match !== null; match = TAG_RE.exec(body)) {
    const text = body.slice(lastIndex, match.index);
    expect(
      text,
      `unescaped '<' in a text node: ${JSON.stringify(text.slice(0, 60))}`,
    ).not.toContain("<");
    for (const entity of text.match(/&[^;]*;?/g) ?? []) {
      expect(entity, `unknown XML entity ${entity}`).toMatch(ENTITY_RE);
    }
    const raw = match[0];
    const closing = match[1] ?? "";
    const name = match[2] ?? "";
    const selfClosing = match[4] ?? "";
    if (closing === "/") {
      expect(stack.pop(), `unbalanced closing tag ${raw}`).toBe(name);
    } else if (selfClosing !== "/") {
      stack.push(name);
    }
    lastIndex = match.index + raw.length;
  }
  expect(body.slice(lastIndex), "text after the final tag").not.toContain("<");
  expect(stack, "unclosed elements").toEqual([]);
}

function bodyOf(response: Response): Promise<string> {
  return response.text();
}

describe("radar RSS feed", () => {
  it("serves well-formed RSS with the documented content type and factual items", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const response = await getFeed(new Request(BASE));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/rss+xml; charset=utf-8");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-ratelimit-limit")).toBe("600");
    const xml = await bodyOf(response);
    assertWellFormed(xml);

    expect(xml).toContain('<rss version="2.0"');
    expect(xml).toContain("<title>CVE Change Radar change feed</title>");
    expect(xml).toContain("Accepted change events derived from local accepted daily CVE snapshots");
    expect(xml).toContain("30-day checkpoint retention window");
    expect(xml).toContain(
      `<lastBuildDate>${new Date(`${D3}T04:00:00.000Z`).toUTCString()}</lastBuildDate>`,
    );

    expect(xml.match(/<item>/g)?.length).toBe(2);
    expect(xml).toContain(`<title>CVE-2099-0002 — kev-added</title>`);
    expect(xml).toContain("<link>https://www.cve.org/CVERecord?id=CVE-2099-0002</link>");
    expect(xml).toContain('<guid isPermaLink="false">radar-');
    expect(xml).toContain(`<pubDate>${new Date(`${D2}T04:00:00.000Z`).toUTCString()}</pubDate>`);
    expect(xml).toContain("kev.listed: false → true");
    expect(xml).toContain(`kev.dateAdded: null → ${D2}`);
    expect(xml).toContain("reason: KEV membership added");
    expect(xml).toContain("sourceRevision: kev-");

    const newest = xml.indexOf("radar-");
    const firstItem = xml.indexOf("<item>");
    expect(newest).toBeGreaterThan(firstItem);
    const ids = [...xml.matchAll(/<guid isPermaLink="false">([^<]+)<\/guid>/g)].map(
      (match) => match[1] ?? "",
    );
    expect(ids).toHaveLength(2);
    expect(ids[0]?.startsWith(`radar-${D2}`)).toBe(true);
    expect(ids[1]?.startsWith(`radar-${D1}`)).toBe(true);
  });

  it("caps items at limit and keeps the newest checkpoint first", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const xml = await bodyOf(await getFeed(new Request(`${BASE}?limit=1`)));
    assertWellFormed(xml);
    expect(xml.match(/<item>/g)?.length).toBe(1);
    expect(xml).toContain("CVE-2099-0002");
    expect(xml).not.toContain("CVE-2099-0001");
  });

  it("narrows by since, kind, and cveId exactly like the JSON route", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const bySince = await bodyOf(await getFeed(new Request(`${BASE}?since=${D2}`)));
    assertWellFormed(bySince);
    expect(bySince.match(/<item>/g)?.length).toBe(1);
    expect(bySince).toContain("CVE-2099-0002");

    const byKind = await bodyOf(await getFeed(new Request(`${BASE}?kind=kev-added`)));
    assertWellFormed(byKind);
    expect(byKind.match(/<item>/g)?.length).toBe(2);

    const emptyKind = await bodyOf(await getFeed(new Request(`${BASE}?kind=rejected`)));
    assertWellFormed(emptyKind);
    expect(emptyKind.match(/<item>/g)).toBeNull();

    const byCve = await bodyOf(await getFeed(new Request(`${BASE}?cveId=CVE-2099-0001`)));
    assertWellFormed(byCve);
    expect(byCve.match(/<item>/g)?.length).toBe(1);
    expect(byCve).toContain("CVE-2099-0001");
  });

  it("rejects a since older than the checkpoint retention window with the earliest date", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const earliestBefore = earliestAllowedCheckpointDate(new Date());
    const response = await getFeed(new Request(`${BASE}?since=2020-01-01`));
    const earliestAfter = earliestAllowedCheckpointDate(new Date());
    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toContain("application/json");
    const body = (await response.json()) as { code: string; message: string };
    expect(body.code).toBe("BAD_FILTER");
    expect(body.message).toContain("30-day checkpoint retention window");
    expect(body.message).toContain("earliest allowed date is");
    const named = body.message.match(/earliest allowed date is (\d{4}-\d{2}-\d{2})/)?.[1];
    expect([earliestBefore, earliestAfter]).toContain(named);
  });

  it("uses the JSON radar route's error codes for malformed params", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const cases: Array<[string, string]> = [
      ["?kind=bogus", "BAD_FILTER"],
      ["?cveId=not-a-cve", "BAD_FILTER"],
      ["?since=2026-02-31", "BAD_FILTER"],
      ["?limit=201", "BAD_LIMIT"],
    ];
    for (const [query, code] of cases) {
      const response = await getFeed(new Request(`${BASE}${query}`));
      expect(response.status, query).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code, query).toBe(code);
    }
  });

  it("escapes &, <, and > in description text", async () => {
    const reason = "AT&T <script>alert(1)</script> > 5";
    const event: RadarFeedEvent = {
      eventId: "radar-2026-11-14-0001",
      observedAt: "2026-11-14T04:00:00.000Z",
      kind: "corrected",
      cveId: "CVE-2099-0001",
      changes: [{ field: "record.state", before: null, after: "PUBLISHED" }],
      sourceRevision: "cve-rev-feed-aaa",
      reason,
    };
    const xml = buildRadarFeed([event], {
      feedUrl: "https://radar.test/api/v1/radar/feed.xml",
      jsonUrl: "https://radar.test/api/v1/radar",
      lastBuildAt: null,
      earliestAllowedDay: "2026-10-15",
      hasRetainedCheckpoints: true,
    });
    assertWellFormed(xml);
    expect(xml).toContain("AT&amp;T &lt;script&gt;alert(1)&lt;/script&gt; &gt; 5");
    expect(xml).not.toContain("<script>");
    expect(xml).toContain("reason: AT&amp;T");
  });

  it("states the empty state explicitly when no checkpoint is retained", async () => {
    // A fresh store has never run the daily writer. An empty item list alone
    // reads as "no changes", so the channel description must say why it is
    // empty and must never claim that nothing changed.
    makeDb();

    const response = await getFeed(new Request(BASE));
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/rss+xml; charset=utf-8");
    const xml = await bodyOf(response);
    assertWellFormed(xml);

    const description = /<description>([\s\S]*?)<\/description>/.exec(xml)?.[1] ?? "";
    expect(description).toContain(
      "No change checkpoints are retained yet; this feed fills as the daily checkpoint writer runs.",
    );
    expect(description).toContain("30-day checkpoint retention window");
    expect(description.toLowerCase()).not.toContain("no changes");
    expect(xml.match(/<item>/g)).toBeNull();
    expect(xml).not.toContain("<lastBuildDate>");
  });

  it("revalidates a repeat request with If-None-Match as 304", async () => {
    const db = makeDb();
    seedRadarFeed(db);

    const first = await getFeed(new Request(BASE));
    const etag = first.headers.get("etag");
    expect(etag).toMatch(/^"[0-9a-f]{64}"$/);
    expect(first.headers.get("cache-control")).toContain("public");

    const cached = await getFeed(new Request(BASE, { headers: { "if-none-match": etag ?? "" } }));
    expect(cached.status).toBe(304);
    expect(await cached.text()).toBe("");
    expect(cached.headers.get("etag")).toBe(etag);
    expect(cached.headers.get("cache-control")).toContain("public");

    const narrowed = await getFeed(new Request(`${BASE}?limit=1`));
    expect(narrowed.headers.get("etag")).not.toBe(etag);
  });

  it("answers OPTIONS with the shared preflight and security headers", async () => {
    const response = await optionsFeed(new Request(BASE, { method: "OPTIONS" }));
    expect(response.status).toBe(204);
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
  });
});
