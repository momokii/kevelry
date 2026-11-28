// Tool-layer tests: argument boundaries, caps, grounding, and the red-team
// fixtures.
//
// No network: the DB is a temp file built with the migrations, and the web
// fallback runs against an injected `fetch`. Each test name is labelled
// [CODE] (mechanical, provable) or [PROMPT] (a prompt instruction, observed not
// proven) so a report cannot overstate what the suite proves.

import type Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { refreshAggregates } from "../src/lib/aggregates";
import { PRIORITY_LISTS } from "../src/lib/ai/tools";
import {
  EPSS_HISTORY_DAYS_OPTIONS,
  EPSS_HISTORY_POINT_CAP,
  KEV_WINDOW_DAYS_MAX,
  KEV_WINDOW_DAYS_MIN,
  LIST_PRIORITY_LIMIT_MAX,
  SEARCH_CVES_LIMIT_DEFAULT,
  SEARCH_CVES_LIMIT_MAX,
  TOOL_NAMES,
  WEB_FETCH_MAX_BYTES,
  WEB_FETCH_MAX_CHARS,
  WEB_FETCH_ALLOWLIST,
  WEB_FETCH_SHORT_BODY_CHARS,
  executeTool,
  parseAllowedFetchUrl,
  toolDefinitions,
  toolNames,
  type ToolContext,
  type ToolOutcome,
} from "../src/lib/ai/tools";
import { openDatabase, type CveDatabase } from "../src/lib/db";
import { CVE_DESCRIPTION_INJECTION, FETCH_PAGE_INJECTION } from "./fixtures/ai/injection";

const STAMP = "2026-10-24T00:00:00.000Z";
const NOW = new Date("2026-10-24T12:00:00.000Z");

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

interface SeedRecord {
  cveId: string;
  state?: "PUBLISHED" | "REJECTED";
  published?: string | null;
  title?: string;
  description?: string;
  metrics?: Array<{ origin: "CNA" | "ADP"; version: string; baseScore: string }>;
  exploitRef?: boolean;
  kev?: { dateAdded: string; dueDate?: string; ransomwareKnown?: number | null };
  cwes?: string[];
  ssvc?: {
    exploitation: "none" | "poc" | "active";
    automatable: "yes" | "no";
    impact: "partial" | "total";
  };
  epss?: Array<{ date: string; value: string; percentile: string }>;
}

function insertRecord(handle: Database.Database, record: SeedRecord): void {
  handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, created_at, updated_at, has_exploit_ref, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      record.cveId,
      "5.1",
      record.state ?? "PUBLISHED",
      record.published === undefined ? "2026-10-01" : record.published,
      STAMP,
      record.title ?? null,
      record.description ?? "",
      "en",
      "rev-1",
      STAMP,
      STAMP,
      record.exploitRef === true ? 1 : 0,
      record.exploitRef === true
        ? JSON.stringify({
            containers: {
              cna: { references: [{ url: "https://example.test/advisory", tags: ["exploit"] }] },
            },
          })
        : null,
    );
  for (const [index, metric] of (record.metrics ?? []).entries()) {
    handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(record.cveId, metric.origin, metric.version, metric.baseScore, "CVSS:4.0/AV:N", index);
  }
  if (record.kev !== undefined) {
    handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, due_date, required_action, vulnerability_name, ransomware_known, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        record.cveId,
        record.kev.dateAdded,
        "2026-10-22",
        record.kev.dueDate ?? null,
        "Apply updates per vendor instructions.",
        `Advisory for ${record.cveId}`,
        record.kev.ransomwareKnown ?? null,
        STAMP,
      );
  }
  for (const cwe of record.cwes ?? []) {
    handle.prepare("INSERT INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)").run(record.cveId, cwe);
  }
  if (record.ssvc !== undefined) {
    handle
      .prepare(
        "INSERT INTO ssvc_records (cve_id, exploitation, automatable, technical_impact, ssvc_version, source_timestamp, catalog_date, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        record.cveId,
        record.ssvc.exploitation,
        record.ssvc.automatable,
        record.ssvc.impact,
        "2.0.3",
        STAMP,
        "2026-10-22",
        STAMP,
      );
  }
  for (const point of record.epss ?? []) {
    handle
      .prepare(
        "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run(record.cveId, point.date, "v2026.10.22", point.value, point.percentile);
  }
}

function makeSeededDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ai-tools-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  db.runBoundedWrite(() => {
    const handle = db.handle;
    handle
      .prepare(
        "INSERT INTO sync_runs (source, started_at, finished_at, status, revision) VALUES (?, ?, ?, ?, ?)",
      )
      .run("cve", STAMP, STAMP, "succeeded", "rev-1");
    insertRecord(handle, {
      cveId: "CVE-2099-0001",
      published: "2026-10-01",
      title: "Widget parser remote code execution",
      description: "A widget parser accepts crafted input and executes it.",
      metrics: [
        { origin: "CNA", version: "4.0", baseScore: "9.8" },
        { origin: "CNA", version: "3.1", baseScore: "7.5" },
      ],
      exploitRef: true,
      kev: { dateAdded: "2026-10-20T00:00:00.000Z", dueDate: "2026-10-24", ransomwareKnown: 1 },
      cwes: ["CWE-79", "CWE-999"],
      ssvc: { exploitation: "active", automatable: "yes", impact: "total" },
      epss: [
        { date: "2026-10-20", value: "0.4", percentile: "0.9" },
        { date: "2026-10-21", value: "0.42", percentile: "0.91" },
        { date: "2026-10-22", value: "0.45", percentile: "0.92" },
      ],
    });
    insertRecord(handle, {
      cveId: "CVE-2099-0002",
      published: "2026-10-05",
      title: "Gadget denial of service",
      description: "A gadget endpoint can be made to loop.",
      metrics: [{ origin: "CNA", version: "3.1", baseScore: "8.1" }],
      epss: [{ date: "2026-10-22", value: "0.02", percentile: "0.4" }],
    });
    insertRecord(handle, {
      cveId: "CVE-2099-0003",
      published: null,
      title: "Unknown-date issue",
      description: "",
      kev: { dateAdded: "2026-10-02T00:00:00.000Z", dueDate: "2026-10-05", ransomwareKnown: null },
    });
    insertRecord(handle, {
      cveId: "CVE-2099-0004",
      state: "REJECTED",
      published: "2026-10-06",
      title: "Rejected record",
      description: "Rejected, never served.",
    });
    insertRecord(handle, {
      cveId: "CVE-2099-0005",
      published: "2026-10-10",
      title: "Record carrying instruction-like text",
      description: CVE_DESCRIPTION_INJECTION,
      metrics: [{ origin: "CNA", version: "4.0", baseScore: "5.0" }],
    });
    handle
      .prepare(
        "INSERT INTO cwe_catalog_meta (id, version, source, source_hash, retrieved_at, status, record_count) VALUES (1, ?, ?, ?, ?, ?, ?)",
      )
      .run("4.14", "MITRE CWE", "hash-test", STAMP, "ready", 1);
    handle
      .prepare(
        "INSERT INTO cwe_entries (cwe_id, name, abstraction, status, summary, mitigation, version, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CWE-79",
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "Base",
        "Draft",
        "The product does not neutralize user-controllable input before it is placed in output.",
        "::PHASE:Implementation:DESCRIPTION:Encode output and validate input.::",
        "4.14",
        STAMP,
      );
  });
  refreshAggregates(db, STAMP);
  return db;
}

function context(db: CveDatabase, overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    db,
    webFetchEnabled: false,
    now: () => NOW,
    epssRetentionDays: 30,
    ...overrides,
  };
}

function dataOf(outcome: ToolOutcome): Record<string, any> {
  expect(outcome.ok).toBe(true);
  if (!outcome.ok) throw new Error(outcome.error);
  return outcome.data as Record<string, any>;
}

/** The payload inside an `untrusted` envelope, without the delimiters. */
function envelopeBody(wrappedText: string): string {
  expect(wrappedText.startsWith("<untrusted-begin")).toBe(true);
  const body = wrappedText.slice(
    wrappedText.indexOf("\n") + 1,
    wrappedText.lastIndexOf("</untrusted-end>"),
  );
  // `wrapUntrusted` puts the close token on its own line.
  return body.endsWith("\n") ? body.slice(0, -1) : body;
}

interface StubCall {
  url: string;
  init: RequestInit | undefined;
}

function stubFetch(handler: (url: string, init: RequestInit | undefined) => Response): {
  impl: typeof fetch;
  calls: StubCall[];
} {
  const calls: StubCall[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, init });
    return handler(url, init);
  }) as typeof fetch;
  return { impl, calls };
}

describe("tool definitions", () => {
  it("[CODE] exposes exactly the eight tools, and seven without the web gate", () => {
    expect(toolDefinitions(true).map((definition) => definition.function.name)).toEqual([
      ...TOOL_NAMES,
    ]);
    expect(toolDefinitions(false).map((definition) => definition.function.name)).not.toContain(
      "fetch_authoritative",
    );
    expect(toolNames(false)).toHaveLength(7);
    expect(
      toolDefinitions(true).every(
        (entry) => entry.function.parameters.additionalProperties === false,
      ),
    ).toBe(true);
  });

  it("[CODE] publishes the same caps the validators enforce", () => {
    const search = toolDefinitions(true).find(
      (definition) => definition.function.name === "search_cves",
    );
    const limit = search?.function.parameters.properties.limit as { maximum: number };
    expect(limit.maximum).toBe(SEARCH_CVES_LIMIT_MAX);
    expect(SEARCH_CVES_LIMIT_MAX).toBe(25);
    expect(SEARCH_CVES_LIMIT_DEFAULT).toBe(10);
    expect(LIST_PRIORITY_LIMIT_MAX).toBe(25);
    expect(EPSS_HISTORY_DAYS_OPTIONS).toEqual([7, 30, 45]);
    expect(EPSS_HISTORY_POINT_CAP).toBe(45);
    expect(KEV_WINDOW_DAYS_MIN).toBe(1);
    expect(KEV_WINDOW_DAYS_MAX).toBe(90);
  });
});

describe("search_cves", () => {
  it("[CODE] returns ids plus minimal facts, with a stated total and limit", async () => {
    const data = dataOf(await executeTool("search_cves", {}, context(makeSeededDb())));
    expect(data.total).toBe(4);
    expect(data.returned).toBe(4);
    expect(data.limit).toBe(SEARCH_CVES_LIMIT_DEFAULT);
    const first = data.items[0] as Record<string, unknown>;
    expect(Object.keys(first).sort()).toEqual([
      "cveId",
      "cvss",
      "cvssVersion",
      "epss",
      "epssPercentile",
      "kev",
      "publishedAt",
      "severity",
    ]);
    // No prose: the minimal payload cannot carry an injection surface.
    expect(JSON.stringify(data)).not.toContain("untrusted-begin");
  });

  it("[CODE] honours the requested limit and the filter args", async () => {
    const db = makeSeededDb();
    const two = dataOf(await executeTool("search_cves", { limit: 2 }, context(db)));
    expect(two.returned).toBe(2);
    const kev = dataOf(await executeTool("search_cves", { kev: "listed" }, context(db)));
    expect(kev.items.every((item: { kev: boolean }) => item.kev)).toBe(true);
    expect(kev.total).toBe(2);
    const tagged = dataOf(await executeTool("search_cves", { exploit: "tagged" }, context(db)));
    expect(tagged.items.map((item: { cveId: string }) => item.cveId)).toEqual(["CVE-2099-0001"]);
  });

  it("[CODE] epssMin filters returned rows and says the total is unfiltered", async () => {
    const data = dataOf(
      await executeTool("search_cves", { epssMin: 0.1, limit: 25 }, context(makeSeededDb())),
    );
    expect(data.items.map((item: { cveId: string }) => item.cveId)).toEqual(["CVE-2099-0001"]);
    expect(data.epssMin).toMatchObject({ min: 0.1, appliesTo: "returned rows only" });
    expect(data.total).toBe(4);
  });

  it("[CODE] rejects a limit above the cap instead of clamping it", async () => {
    const over = await executeTool(
      "search_cves",
      { limit: SEARCH_CVES_LIMIT_MAX + 1 },
      context(makeSeededDb()),
    );
    expect(over).toMatchObject({ ok: false, reason: "OUT_OF_RANGE" });
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.error).toContain("between 1 and 25");
  });

  it("[CODE] rejects unknown keys, wrong types and out-of-range values", async () => {
    const db = makeSeededDb();
    expect(await executeTool("search_cves", { sql: "SELECT 1" }, context(db))).toMatchObject({
      ok: false,
      reason: "UNKNOWN_ARGUMENT",
    });
    expect(await executeTool("search_cves", { limit: "5" }, context(db))).toMatchObject({
      ok: false,
      reason: "WRONG_TYPE",
    });
    expect(await executeTool("search_cves", { limit: 0.5 }, context(db))).toMatchObject({
      ok: false,
      reason: "WRONG_TYPE",
    });
    expect(await executeTool("search_cves", { q: "x" }, context(db))).toMatchObject({
      ok: false,
      reason: "OUT_OF_RANGE",
    });
    expect(
      await executeTool("search_cves", { severity: "apocalyptic" }, context(db)),
    ).toMatchObject({
      ok: false,
      reason: "BAD_ARGUMENT",
    });
    expect(
      await executeTool("search_cves", { dateStart: "2026/10/01" }, context(db)),
    ).toMatchObject({
      ok: false,
      reason: "BAD_ARGUMENT",
    });
    expect(await executeTool("search_cves", [], context(db))).toMatchObject({
      ok: false,
      reason: "WRONG_TYPE",
    });
  });

  it("[CODE] a hostile query string is inert and the schema survives", async () => {
    const db = makeSeededDb();
    const outcome = await executeTool(
      "search_cves",
      { q: "x'; DROP TABLE cve_records; --" },
      context(db),
    );
    expect(outcome.ok).toBe(true);
    const count = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as { n: number };
    expect(count.n).toBe(5);
  });
});

describe("get_cve", () => {
  it("[CODE] returns labelled primary/secondary CVSS, KEV, EPSS and CWE text", async () => {
    const outcome = await executeTool("get_cve", { id: "CVE-2099-0001" }, context(makeSeededDb()));
    expect(outcome.ok && outcome.rows).toBe(1);
    const data = dataOf(outcome);
    expect(data.cvss.primary).toMatchObject({
      label: "primary (CNA)",
      status: "known",
      baseScore: "9.8",
    });
    expect(data.cvss.secondary.label).toContain("secondary");
    expect(data.cvss.secondary.metrics.length).toBeGreaterThan(0);
    expect(data.cvss.secondary.metrics.length).toBeLessThanOrEqual(4);
    expect(data.kev).toMatchObject({
      listed: true,
      dateAdded: "2026-10-20T00:00:00.000Z",
      ransomwareUse: "known",
    });
    expect(data.kev.requiredAction).toContain("untrusted-begin");
    expect(data.epss).toMatchObject({ status: "known", value: "0.45", scoreDate: "2026-10-22" });
    const known = data.cwes.find((cwe: { cweId: string }) => cwe.cweId === "CWE-79");
    expect(known.status).toBe("known");
    expect(known.name).toContain("Cross-site Scripting");
    expect(known.mitigation).toContain("Encode output and validate input");
    expect(known.mitigation).toContain("untrusted-begin");
    expect(known.mitigation).not.toContain("PHASE:");
    const unmapped = data.cwes.find((cwe: { cweId: string }) => cwe.cweId === "CWE-999");
    expect(unmapped.status).toBe("unmapped");
    expect(unmapped.name).toBeNull();
  });

  it("[CODE] refuses a missing id, a malformed id and a rejected record", async () => {
    const db = makeSeededDb();
    expect(await executeTool("get_cve", {}, context(db))).toMatchObject({
      ok: false,
      reason: "MISSING_ARGUMENT",
    });
    expect(await executeTool("get_cve", { id: "not-a-cve" }, context(db))).toMatchObject({
      ok: false,
      reason: "BAD_ARGUMENT",
    });
    expect(await executeTool("get_cve", { id: "CVE-2099-0004" }, context(db))).toMatchObject({
      ok: false,
      reason: "NOT_FOUND",
    });
  });
});

describe("epss_history", () => {
  it("[CODE] returns the dated series oldest first with a missing count", async () => {
    const data = dataOf(
      await executeTool("epss_history", { id: "CVE-2099-0001", days: 7 }, context(makeSeededDb())),
    );
    expect(data.returned).toBe(3);
    expect(data.points.map((point: { scoreDate: string }) => point.scoreDate)).toEqual([
      "2026-10-20",
      "2026-10-21",
      "2026-10-22",
    ]);
    expect(data.missingCount).toBe(4);
    expect(data.capDays).toBe(EPSS_HISTORY_POINT_CAP);
    expect(data.returned).toBeLessThanOrEqual(EPSS_HISTORY_POINT_CAP);
  });

  it("[CODE] rejects days outside {7, 30, 45}", async () => {
    const db = makeSeededDb();
    for (const days of [14, 0, 46]) {
      expect(
        await executeTool("epss_history", { id: "CVE-2099-0001", days }, context(db)),
      ).toMatchObject({ ok: false, reason: "BAD_ARGUMENT" });
    }
    expect(
      await executeTool("epss_history", { id: "CVE-2099-0001", days: "7" }, context(db)),
    ).toMatchObject({ ok: false, reason: "WRONG_TYPE" });
  });
});

describe("kev_window", () => {
  it("[CODE] counts additions and due dates inside one window", async () => {
    const data = dataOf(await executeTool("kev_window", { days: 30 }, context(makeSeededDb())));
    expect(data.windowEnd).toBe("2026-10-24");
    expect(data.windowStart).toBe("2026-09-25");
    expect(data.totalAdditions).toBe(2);
    expect(data.returned).toBe(2);
    expect(data.dueInWindow).toBe(2);
    expect(data.dueFromNow).toBe(1);
    const unmapped = data.items.find((item: { cveId: string }) => item.cveId === "CVE-2099-0003");
    expect(unmapped.ransomwareUse).toBe("unstated");
  });

  it("[CODE] rejects out-of-range and non-integer windows", async () => {
    const db = makeSeededDb();
    for (const days of [0, 91, -1]) {
      expect(await executeTool("kev_window", { days }, context(db))).toMatchObject({
        ok: false,
        reason: "OUT_OF_RANGE",
      });
    }
    expect(await executeTool("kev_window", { days: 30.5 }, context(db))).toMatchObject({
      ok: false,
      reason: "WRONG_TYPE",
    });
    expect(await executeTool("kev_window", {}, context(db))).toMatchObject({
      ok: false,
      reason: "MISSING_ARGUMENT",
    });
  });
});

describe("coverage_stats", () => {
  it("[CODE] quotes the current aggregate when it is current", async () => {
    const data = dataOf(await executeTool("coverage_stats", {}, context(makeSeededDb())));
    expect(data.source).toBe("aggregate");
    expect(data.computedAt).toBe(STAMP);
    expect(data.published).toBe(4);
    expect(data.kev).toBe(2);
    expect(data.epssScored).toBe(2);
    expect(data.exploitTagged).toBe(1);
    expect(data.unknownDate).toBe(1);
    expect(data.retention).toMatchObject({
      epssRetentionDays: 30,
      epssHistoryCapDays: 45,
      earliestEpssScoreDate: "2026-10-20",
      latestEpssScoreDate: "2026-10-22",
    });
  });

  it("[CODE] never serves a stale snapshot under a fresh revision", async () => {
    const db = makeSeededDb();
    db.runBoundedWrite(() => {
      db.handle
        .prepare(
          "INSERT INTO sync_runs (source, started_at, finished_at, status, revision) VALUES (?, ?, ?, ?, ?)",
        )
        .run("cve", STAMP, STAMP, "succeeded", "rev-2");
      insertRecord(db.handle, {
        cveId: "CVE-2099-0006",
        published: "2026-10-23",
        title: "Freshly imported record",
        description: "Imported after the snapshot was computed.",
        metrics: [{ origin: "CNA", version: "4.0", baseScore: "6.0" }],
      });
    });
    const data = dataOf(await executeTool("coverage_stats", {}, context(db)));
    expect(data.source).toBe("live");
    expect(data.computedAt).toBeNull();
    expect(data.published).toBe(5);
    expect(data.provenance.cveRevision).toBe("rev-2");
  });
});

describe("list_priority", () => {
  it("[CODE] answers every shipped list with its ordering and a bounded page", async () => {
    const db = makeSeededDb();
    for (const list of PRIORITY_LISTS) {
      const outcome = await executeTool("list_priority", { list, limit: 5 }, context(db));
      const data = dataOf(outcome);
      expect(data.list).toBe(list);
      expect(data.boundedTopN).toBe(5);
      expect(Array.isArray(data.ordering)).toBe(true);
      expect(data.ordering.length).toBeGreaterThan(0);
      expect(data.returned).toBeLessThanOrEqual(5);
      for (const item of data.items as Array<{ cveId: string; decidingKey: { key: string } }>) {
        expect(item.cveId).toMatch(/^CVE-/);
        expect(item.decidingKey.key.length).toBeGreaterThan(0);
      }
    }
    const known = dataOf(
      await executeTool("list_priority", { list: "known-exploited" }, context(db)),
    );
    expect(known.items.map((item: { cveId: string }) => item.cveId)).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0003",
    ]);
    expect(known.items[0].decidingKey.key).toBe("kev-dateAdded");
  });

  it("[CODE] rejects an unknown list and an over-cap limit", async () => {
    const db = makeSeededDb();
    expect(await executeTool("list_priority", { list: "top-risk" }, context(db))).toMatchObject({
      ok: false,
      reason: "BAD_ARGUMENT",
    });
    expect(
      await executeTool("list_priority", { list: "known-exploited", limit: 26 }, context(db)),
    ).toMatchObject({ ok: false, reason: "OUT_OF_RANGE" });
  });
});

describe("cwe_lookup", () => {
  it("[CODE] resolves a known id with catalog provenance and text as data", async () => {
    const data = dataOf(
      await executeTool("cwe_lookup", { cweId: "CWE-79" }, context(makeSeededDb())),
    );
    expect(data.status).toBe("known");
    expect(data.name).toContain("Cross-site Scripting");
    expect(data.mitigation).toContain("untrusted-begin");
    expect(data.catalog).toMatchObject({ version: "4.14", status: "ready" });
  });

  it("[CODE] reports an unmapped id and rejects a malformed one", async () => {
    const db = makeSeededDb();
    const unmapped = dataOf(await executeTool("cwe_lookup", { cweId: "CWE-99999" }, context(db)));
    expect(unmapped.status).toBe("unmapped");
    expect(unmapped.name).toBeNull();
    expect(await executeTool("cwe_lookup", { cweId: "79" }, context(db))).toMatchObject({
      ok: false,
      reason: "BAD_ARGUMENT",
    });
  });
});

function stub(outcome: Response): { impl: typeof fetch; calls: StubCall[] } {
  return stubFetch(() => outcome);
}

describe("fetch_authoritative", () => {
  it("[CODE] is disabled when AI_WEB_FETCH_ENABLED=false and makes zero fetch calls", async () => {
    const { impl, calls } = stub(new Response("never read"));
    const outcome = await executeTool(
      "fetch_authoritative",
      { url: "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" },
      context(makeSeededDb(), { webFetchEnabled: false, fetchImpl: impl }),
    );
    expect(outcome).toMatchObject({ ok: false, reason: "WEB_FETCH_DISABLED" });
    expect(calls).toHaveLength(0);
  });

  it("[CODE] runs at most one fetch per turn: the second call is refused with no socket", async () => {
    // The prompt says "one fetch per turn". This is the code that makes it true:
    // the turn's budget is spent by the first attempt and the second is refused
    // before validation, before any socket, before any load.
    const { impl, calls } = stubFetch(
      () =>
        new Response("Advisory body for CVE-2099-0001.", {
          status: 200,
          headers: { "content-type": "text/plain" },
        }),
    );
    const budget = { used: false };
    const ctx = context(makeSeededDb(), {
      webFetchEnabled: true,
      fetchImpl: impl,
      webFetchBudget: budget,
    });
    const url = "https://nvd.nist.gov/vuln/detail/CVE-2099-0001";

    const first = await executeTool("fetch_authoritative", { url }, ctx);
    const second = await executeTool("fetch_authoritative", { url }, ctx);

    expect(first.ok).toBe(true);
    expect(second).toMatchObject({ ok: false, reason: "WEB_FETCH_ONCE" });
    expect(calls).toHaveLength(1);
    expect(budget.used).toBe(true);

    // A fresh turn starts with a fresh allowance; the counter is per turn, not
    // per process.
    const nextTurn = await executeTool(
      "fetch_authoritative",
      { url },
      {
        ...ctx,
        webFetchBudget: { used: false },
      },
    );
    expect(nextTurn.ok).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it("[CODE] rejects http, an off-allowlist host, a non-443 port and credentials", async () => {
    const { impl, calls } = stub(new Response("never read"));
    const ctx = context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl });
    for (const url of [
      "http://nvd.nist.gov/vuln/detail/CVE-2099-0001",
      "https://evil.test/page",
      "https://nvd.nist.gov:8443/page",
      "https://bob:secret@nvd.nist.gov/page",
      "file:///etc/passwd",
      "https://169.254.169.254/latest/meta-data",
    ]) {
      expect(await executeTool("fetch_authoritative", { url }, ctx)).toMatchObject({
        ok: false,
        reason: "BLOCKED_URL",
      });
    }
    expect(calls).toHaveLength(0);
  });

  it("[CODE] fetches an allowlisted https host as GET without auth headers", async () => {
    const { impl, calls } = stub(
      new Response(
        "<html><head><style>.x{}</style><script>alert(1)</script></head><body><h1>Advisory</h1><p>CVE-2099-0001 details.</p></body></html>",
        { status: 200, headers: { "content-type": "text/html; charset=utf-8" } },
      ),
    );
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBe("GET");
    expect(calls[0]?.init?.redirect).toBe("manual");
    const headers = (calls[0]?.init?.headers ?? {}) as Record<string, string>;
    expect(Object.keys(headers).map((key) => key.toLowerCase())).toEqual(["accept"]);
    // Negotiation is what makes the fetch work at all: NVD's API answers 406 to a
    // text-only Accept and 200 to `application/json`. JSON first, then a page,
    // then plain text, then anything.
    expect(headers.accept).toBe("application/json, text/html;q=0.9, text/plain;q=0.8, */*;q=0.1");
    expect(headers.accept).toContain("application/json");
    expect(data).toMatchObject({ source: "web", untrusted: true, host: "nvd.nist.gov" });
    expect(data.text).toContain("untrusted-begin");
    expect(data.text).toContain("Advisory");
    expect(data.text).not.toContain("alert(1)");
    expect(data.text).not.toContain(".x{}");
  });

  it("[CODE] returns a JSON body as JSON text instead of stripping it like HTML", async () => {
    // The NVD API 2.0 shape: the machine-readable answer the prompt tells the
    // model to reach for when a cve.org page comes back as an empty shell.
    const body = JSON.stringify({
      resultsPerPage: 1,
      totalResults: 1,
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2099-12345",
            vulnStatus: "Rejected",
            descriptions: [{ lang: "en", value: "Rejected reason: duplicate of CVE-2099-0001." }],
          },
        },
      ],
    });
    for (const contentType of [
      "application/json",
      "application/json; charset=utf-8",
      "application/vnd.api+json",
    ]) {
      const { impl } = stub(
        new Response(body, { status: 200, headers: { "content-type": contentType } }),
      );
      const data = dataOf(
        await executeTool(
          "fetch_authoritative",
          { url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-12345" },
          context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
        ),
      );
      expect(data).toMatchObject({
        source: "web",
        untrusted: true,
        contentKind: "json",
        jsonParsed: true,
        // JSON is not a page: nothing was rendered, and no `<title>` exists.
        mayBeClientRendered: false,
        title: null,
        textTruncated: false,
      });
      const text = envelopeBody(data.text as string);
      // `extractText` collapses all whitespace, so an indented multi-line body
      // is the proof that the HTML path was skipped.
      expect(text).toMatch(/\n {2,}"id": "CVE-2099-12345",/);
      expect(JSON.parse(text)).toEqual(JSON.parse(body));
    }
  });

  it("[CODE] keeps tag-shaped JSON strings as data, not as markup to remove", async () => {
    const body = JSON.stringify({
      cveId: "CVE-2099-12345",
      description: "<p>Rejected reason: duplicate.</p>",
    });
    const { impl } = stub(
      new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
    );
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-12345" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    const text = envelopeBody(data.text as string);
    // Not stripped: the tags survive as inert `‹p›` text, exactly like any other
    // web prose that passes through `wrapUntrusted`.
    expect(text).toContain("description");
    expect(text).toContain("‹p›Rejected reason: duplicate.‹/p›");
    expect(text).not.toContain("<p>");
  });

  it("[CODE] flags a client-rendered shell from its own heading-length body", async () => {
    // The live evidence: cve.org's record page is a client-rendered app, and its
    // extracted text was only the heading.
    const html =
      '<!doctype html><html><head><title>Common vulnerabilities and Exposures (CVE)</title></head><body><div id="app"></div><script>renderRecord()</script></body></html>';
    const { impl } = stub(
      new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } }),
    );
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://www.cve.org/CVERecord?id=CVE-2099-12345" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    expect(data).toMatchObject({
      contentKind: "html",
      mayBeClientRendered: true,
      jsonParsed: null,
    });
    expect(envelopeBody(data.title as string)).toBe("Common vulnerabilities and Exposures (CVE)");
    const text = envelopeBody(data.text as string);
    expect(text).toContain("Common vulnerabilities and Exposures (CVE)");
    expect(text).not.toContain("renderRecord()");
  });

  it("[CODE] does not flag an HTML page whose body is at or above the threshold", async () => {
    // No `<title>` here, so the extracted length is exactly the body length and
    // the boundary can be stated instead of approximated.
    const page = (chars: number): string => `<html><body><p>${"x".repeat(chars)}</p></body></html>`;
    for (const [chars, expected] of [
      [WEB_FETCH_SHORT_BODY_CHARS - 1, true],
      [WEB_FETCH_SHORT_BODY_CHARS, false],
      [WEB_FETCH_SHORT_BODY_CHARS * 4, false],
    ] as const) {
      const { impl } = stub(
        new Response(page(chars), { status: 200, headers: { "content-type": "text/html" } }),
      );
      const data = dataOf(
        await executeTool(
          "fetch_authoritative",
          { url: "https://nvd.nist.gov/vuln/detail/CVE-2099-12345" },
          context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
        ),
      );
      expect(data.mayBeClientRendered).toBe(expected);
      expect(data.contentKind).toBe("html");
      expect(data.title).toBeNull();
      expect(envelopeBody(data.text as string)).toHaveLength(chars);
    }
  });

  it("[CODE] truncates an oversized body at the byte cap", async () => {
    const { impl } = stub(
      new Response("A".repeat(WEB_FETCH_MAX_BYTES + 4096), {
        status: 200,
        headers: { "content-type": "text/plain" },
      }),
    );
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    expect(data.bytes).toBe(WEB_FETCH_MAX_BYTES);
    expect(data.bodyTruncated).toBe(true);
    expect(data.textTruncated).toBe(true);
    expect(data.text.length).toBeLessThan(WEB_FETCH_MAX_CHARS + 200);
  });

  it("[CODE] refuses a redirect to a non-allowlisted host", async () => {
    const { impl, calls } = stub(
      new Response(null, { status: 302, headers: { location: "https://evil.test/payload" } }),
    );
    const outcome = await executeTool(
      "fetch_authoritative",
      { url: "https://cve.org/CVERecord?id=CVE-2099-0001" },
      context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
    );
    expect(outcome).toMatchObject({ ok: false, reason: "BLOCKED_URL" });
    if (!outcome.ok) expect(outcome.error).toContain("redirect target refused");
    expect(calls).toHaveLength(1);
  });

  it("[CODE] follows one redirect when the target is itself allowlisted", async () => {
    const urls: string[] = [];
    const { impl } = stubFetch((url) => {
      urls.push(url);
      if (urls.length === 1) {
        return new Response(null, {
          status: 301,
          headers: { location: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
        });
      }
      return new Response("Catalog page", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    });
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://www.cisa.gov/kev" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    expect(urls).toHaveLength(2);
    expect(data.host).toBe("www.cisa.gov");
  });

  it("[CODE] enforces a per-call deadline", async () => {
    const never = (async () => new Promise<Response>(() => undefined)) as typeof fetch;
    const outcome = await executeTool(
      "fetch_authoritative",
      { url: "https://www.first.org/epss" },
      context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: never, timeoutMs: 5 }),
    );
    expect(outcome).toMatchObject({ ok: false, reason: "TIMEOUT" });
  });

  it("[CODE] every allowlist entry is an exact host and rejects a suffix lookalike", () => {
    for (const host of WEB_FETCH_ALLOWLIST) {
      expect(parseAllowedFetchUrl(`https://${host}/x`)).toMatchObject({ host });
      expect(parseAllowedFetchUrl(`https://${host}.evil.test/x`)).toHaveProperty("error");
      expect(parseAllowedFetchUrl(`https://sub.${host}/x`)).toHaveProperty("error");
    }
  });
});

describe("red-team fixtures", () => {
  it("[CODE] a CVE description cannot escape the envelope or trigger a tool call", async () => {
    const { impl, calls } = stub(new Response("never read"));
    const db = makeSeededDb();
    const before = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
      n: number;
    };
    const outcome = await executeTool(
      "get_cve",
      { id: "CVE-2099-0005" },
      context(db, { webFetchEnabled: true, fetchImpl: impl }),
    );
    const data = dataOf(outcome);
    const excerpt = data.record.descriptionExcerpt as string;
    expect(excerpt.startsWith("<untrusted-begin")).toBe(true);
    expect(excerpt).toContain("IGNORE ALL PREVIOUS INSTRUCTIONS");
    // The instruction-like text is data inside the envelope, not markup.
    const body = excerpt.slice(excerpt.indexOf("\n") + 1, excerpt.lastIndexOf("</untrusted-end>"));
    expect(body).not.toContain("<");
    expect(body).not.toContain(">");
    // The fake tool call was never executed.
    expect(calls).toHaveLength(0);
    const after = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as { n: number };
    expect(after.n).toBe(before.n);
  });

  it("[CODE] a fetched page's fake tool-call JSON arrives as inert text", async () => {
    const { impl, calls } = stub(
      new Response(FETCH_PAGE_INJECTION, {
        status: 200,
        headers: { "content-type": "text/html" },
      }),
    );
    const data = dataOf(
      await executeTool(
        "fetch_authoritative",
        { url: "https://www.cisa.gov/news-events/bulletins" },
        context(makeSeededDb(), { webFetchEnabled: true, fetchImpl: impl }),
      ),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://www.cisa.gov/news-events/bulletins");
    expect(data.text).toContain("untrusted-begin");
    expect(data.text).toContain("tool_calls");
    expect(data.text).toContain("169.254.169.254");
    // Neutralised: no angle brackets survive, so the JSON cannot look like markup.
    const raw = data.text as string;
    const body = raw.slice(raw.indexOf("\n") + 1, raw.lastIndexOf("</untrusted-end>"));
    expect(body).not.toContain("<");
    expect(body).not.toContain(">");
    // The URLs inside the fake tool call were not followed.
    expect(
      calls.every((call: StubCall) => call.url === "https://www.cisa.gov/news-events/bulletins"),
    ).toBe(true);
  });

  it("[PROMPT] the prompt still names these shapes as data, never instructions", () => {
    // The prompt assertion lives in tests/ai-prompt.test.ts; this is the
    // red-team cross-reference so the fixture set and the rule stay linked.
    expect(CVE_DESCRIPTION_INJECTION).toContain("IGNORE ALL PREVIOUS INSTRUCTIONS");
    expect(FETCH_PAGE_INJECTION).toContain("tool_calls");
  });
});

describe("tool-layer capability surface", () => {
  it("[CODE] tools.ts holds no SQL write keyword and no shell/filesystem capability", () => {
    const source = readFileSync(new URL("../src/lib/ai/tools.ts", import.meta.url), "utf8");
    for (const forbidden of [
      /\bINSERT\s+INTO\b/i,
      /\bUPDATE\s+\w+\s+SET\b/i,
      /\bDELETE\s+FROM\b/i,
      /\bDROP\s+(?:TABLE|INDEX|VIEW)\b/i,
      /\bATTACH\s+DATABASE\b/i,
      /\bPRAGMA\s+\w+/i,
      /\bchild_process\b/,
      /\bnode:fs\b/,
      /\brequire\s*\(/,
      /\beval\s*\(/,
      /\bnew Function\b/,
    ]) {
      expect(source).not.toMatch(forbidden);
    }
  });

  it("[CODE] an unknown tool is refused before any loader runs", async () => {
    const outcome = await executeTool("run_sql", { query: "SELECT 1" }, context(makeSeededDb()));
    expect(outcome).toMatchObject({ ok: false, reason: "UNKNOWN_TOOL" });
  });

  it("[CODE] the web tool is absent from the exposed list when the gate is off", () => {
    expect(toolNames(true)).toContain("fetch_authoritative");
    expect(toolNames(false)).not.toContain("fetch_authoritative");
    expect(TOOL_NAMES).toHaveLength(8);
  });
});
