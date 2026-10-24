// New-test justification (plan todo 16): the public API is the only
// network surface, so tests must prove the hardening contract at the route
// layer: the documented 600/minute per-IP budget with Retry-After and
// rate-limit headers, request size bounds, a wall-clock budget that turns
// expensive queries into safe generic errors, a concurrency cap that sheds
// load as 429, a strict CORS allow-list that never reflects arbitrary
// origins, security headers (CSP with frame-ancestors, nosniff, no-referrer)
// on every response, sanitized error bodies with no internals, SSRF-shaped
// input rejected at the boundary, and no raw database or data-directory
// routes. Fixture IDs are invented CVE-2099 values; nothing touches the
// network.

import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import { writeCheckpoint } from "../src/lib/radar";
import {
  acquireConcurrencySlot,
  checkRateLimit,
  RATE_LIMIT_MAX,
  RATE_LIMIT_WINDOW_SECONDS,
  releaseConcurrencySlot,
  resetDbOverride,
  resetHardeningState,
  setAllowedOrigins,
  setMaxConcurrentRequests,
  setSearchBudgetMs,
  setDbOverride,
} from "../app/api/v1/_lib/shared";
import { GET as getCves, OPTIONS as optionsCves } from "../app/api/v1/cves/route";
import { GET as getCveById } from "../app/api/v1/cves/[cveId]/route";
import { GET as getSearch } from "../app/api/v1/search/route";
import { GET as getPriority } from "../app/api/v1/priority/[listName]/route";
import { GET as getRadar } from "../app/api/v1/radar/route";
import { GET as getReplay } from "../app/api/v1/replay/route";
import { GET as getCheckpoints } from "../app/api/v1/replay/checkpoints/route";
import { GET as getOverview } from "../app/api/v1/overview/route";
import { GET as getStatus } from "../app/api/v1/status/route";
import { GET as getHealth, OPTIONS as optionsHealth } from "../app/api/v1/health/route";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

const MODEL = "v2026.06.15";
const STAMP = "2026-10-24T00:00:00.000Z";

function isoDay(offsetDays: number): string {
  return new Date(Date.now() + offsetDays * 86_400_000).toISOString().slice(0, 10);
}

const SCORE_DATE = isoDay(-1);
const CHECKPOINT_A = isoDay(-1);
const CHECKPOINT_B = isoDay(0);

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-api-hardening-test-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  setDbOverride(db);
  return db;
}

afterEach(() => {
  resetHardeningState();
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

function seedMinimal(db: CveDatabase): void {
  db.runBoundedWrite(() => {
    const record = db.handle.prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    record.run(
      "CVE-2099-0001",
      "5.1",
      "PUBLISHED",
      "2026-10-20T00:00:00.000Z",
      "CVE-2099-0001",
      "A denial of service flaw was found in the packet parser when handling fragmented datagrams",
      "en",
      "rev-test-aaa",
      null,
      STAMP,
      STAMP,
    );
    record.run(
      "CVE-2099-0002",
      "5.1",
      "PUBLISHED",
      "2026-10-19T00:00:00.000Z",
      "CVE-2099-0002",
      "A use-after-free in the renderer with moderate impact",
      "en",
      "rev-test-aaa",
      null,
      STAMP,
      STAMP,
    );
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", "CNA", "3.1", "9.8", "CVSS:3.1/AV:N", 0);
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
      )
      .run("CVE-2099-0001", SCORE_DATE, MODEL, "0.1162", "0.96047");
    const sync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    sync.run("cve", STAMP, STAMP, "succeeded", "rev-test-aaa", "hash-cve", null);
    sync.run("kev", STAMP, STAMP, "succeeded", "2026.10.23", "hash-kev", null);
    sync.run("epss", STAMP, STAMP, "succeeded", `${SCORE_DATE}@${MODEL}`, "hash-epss", null);
  });
  const pins = {
    cveRevision: "rev-test-aaa",
    kevCatalogDate: "2026-10-22",
    epssScoreDate: SCORE_DATE,
    epssModelVersion: MODEL,
  };
  writeCheckpoint(db, {
    checkpointDate: CHECKPOINT_A,
    observedAt: `${CHECKPOINT_A}T04:00:00.000Z`,
    sourcePins: pins,
    policyVersion: "ranking-v1",
  });
  db.runBoundedWrite(() => {
    db.handle
      .prepare("INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)")
      .run("CVE-2099-0001", CHECKPOINT_B, "2026.10.23", STAMP);
  });
  writeCheckpoint(db, {
    checkpointDate: CHECKPOINT_B,
    observedAt: `${CHECKPOINT_B}T04:00:00.000Z`,
    sourcePins: { ...pins, kevCatalogDate: "2026-10-23" },
    policyVersion: "ranking-v1",
  });
}

async function bodyOf(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

function expectRateHeaders(response: Response): void {
  expect(response.headers.get("x-ratelimit-limit")).toBe("600");
  expect(Number(response.headers.get("x-ratelimit-remaining"))).toBeGreaterThanOrEqual(0);
  expect(Number(response.headers.get("x-ratelimit-reset"))).toBeGreaterThanOrEqual(0);
}

function expectSecurityHeaders(response: Response): void {
  expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  expect(response.headers.get("x-frame-options")).toBe("DENY");
  const csp = response.headers.get("content-security-policy") ?? "";
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("default-src 'none'");
  expect(response.headers.get("referrer-policy")).toBe("no-referrer");
}

function withIp(url: string, ip: string, init?: RequestInit): Request {
  return new Request(url, {
    ...init,
    headers: { ...(init?.headers ?? {}), "x-forwarded-for": ip },
  });
}

describe("rate budget", () => {
  it("enforces the documented 600/minute per-IP budget with Retry-After", async () => {
    makeDb();
    expect(RATE_LIMIT_MAX).toBe(600);
    expect(RATE_LIMIT_WINDOW_SECONDS).toBe(60);

    const ip = "10.9.9.9";
    for (let n = 0; n < RATE_LIMIT_MAX; n += 1) {
      expect(checkRateLimit(ip).allowed, `hit ${n + 1} allowed`).toBe(true);
    }
    const spent = checkRateLimit(ip);
    expect(spent.allowed).toBe(false);
    expect(spent.remaining).toBe(0);

    const limited = await getHealth(withIp("https://radar.test/api/v1/health", ip));
    expect(limited.status).toBe(429);
    const limitedBody = await bodyOf(limited);
    expect(limitedBody.code).toBe("RATE_LIMITED");
    expectRateHeaders(limited);
    expectSecurityHeaders(limited);
    const retryAfter = Number(limited.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect((limitedBody.provenance as Record<string, unknown>).rankingPolicyVersion).toBe("ranking-v1");

    const other = await getHealth(withIp("https://radar.test/api/v1/health", "10.9.9.10"));
    expect(other.status).toBe(200);
  });
});

describe("headers on every route", () => {
  it("serves rate-limit and security headers from all ten GET routes", async () => {
    const db = makeDb();
    seedMinimal(db);
    void db;

    const calls: Promise<Response>[] = [
      getCves(new Request("https://radar.test/api/v1/cves")),
      getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-0001"), {
        params: Promise.resolve({ cveId: "CVE-2099-0001" }),
      }),
      getSearch(new Request("https://radar.test/api/v1/search?q=packet%20parser")),
      getPriority(new Request("https://radar.test/api/v1/priority/known-exploited"), {
        params: Promise.resolve({ listName: "known-exploited" }),
      }),
      getRadar(new Request("https://radar.test/api/v1/radar")),
      getReplay(
        new Request(`https://radar.test/api/v1/replay?date=${CHECKPOINT_B}&view=highest-forecast`),
      ),
      getCheckpoints(new Request("https://radar.test/api/v1/replay/checkpoints")),
      getOverview(new Request("https://radar.test/api/v1/overview")),
      getStatus(new Request("https://radar.test/api/v1/status")),
      getHealth(new Request("https://radar.test/api/v1/health")),
    ];
    const responses = await Promise.all(calls);
    expect(responses).toHaveLength(10);
    for (const response of responses) {
      expect(response.status).toBe(200);
      expectRateHeaders(response);
      expectSecurityHeaders(response);
    }
  });
});

describe("strict CORS allow-list", () => {
  it("never reflects unlisted origins and echoes listed ones", async () => {
    makeDb();

    const denied = await getHealth(
      new Request("https://radar.test/api/v1/health", { headers: { origin: "https://evil.test" } }),
    );
    expect(denied.status).toBe(200);
    expect(denied.headers.get("access-control-allow-origin")).toBeNull();
    expect(denied.headers.get("vary")).toBe("Origin");

    const noOrigin = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(noOrigin.headers.get("access-control-allow-origin")).toBeNull();

    setAllowedOrigins(["https://app.test"]);
    const allowed = await getHealth(
      new Request("https://radar.test/api/v1/health", { headers: { origin: "https://app.test" } }),
    );
    expect(allowed.headers.get("access-control-allow-origin")).toBe("https://app.test");
    expect(allowed.headers.get("vary")).toBe("Origin");

    const stillDenied = await getHealth(
      new Request("https://radar.test/api/v1/health", { headers: { origin: "https://evil.test" } }),
    );
    expect(stillDenied.headers.get("access-control-allow-origin")).toBeNull();

    const preflightAllowed = await optionsHealth(
      new Request("https://radar.test/api/v1/health", {
        method: "OPTIONS",
        headers: { origin: "https://app.test" },
      }),
    );
    expect(preflightAllowed.status).toBe(204);
    expect(preflightAllowed.headers.get("access-control-allow-origin")).toBe("https://app.test");
    expectSecurityHeaders(preflightAllowed);

    const preflightDenied = await optionsCves(
      new Request("https://radar.test/api/v1/cves", {
        method: "OPTIONS",
        headers: { origin: "https://evil.test" },
      }),
    );
    expect(preflightDenied.status).toBe(204);
    expect(preflightDenied.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("request size bounds", () => {
  it("rejects oversized request lines, param floods, and long cursors", async () => {
    makeDb();

    const longUrl = `https://radar.test/api/v1/health?pad=${"p".repeat(4200)}`;
    const oversized = await getHealth(new Request(longUrl));
    expect(oversized.status).toBe(400);
    expect((await bodyOf(oversized)).code).toBe("BAD_REQUEST");
    expectRateHeaders(oversized);
    expectSecurityHeaders(oversized);

    const flood = `https://radar.test/api/v1/health?${Array.from({ length: 26 }, (_, n) => `p${n}=1`).join("&")}`;
    const flooded = await getHealth(new Request(flood));
    expect(flooded.status).toBe(400);
    expect((await bodyOf(flooded)).code).toBe("BAD_REQUEST");

    const longCursor = await getCves(
      new Request(`https://radar.test/api/v1/cves?cursor=${"y".repeat(600)}`),
    );
    expect(longCursor.status).toBe(400);
    expect((await bodyOf(longCursor)).code).toBe("BAD_CURSOR");
  });
});

describe("expensive queries time out safely", () => {
  it("turns an over-budget search into a generic 500 without internals", async () => {
    const db = makeDb();
    seedMinimal(db);
    void db;

    setSearchBudgetMs(0);
    const timedOut = await getSearch(new Request("https://radar.test/api/v1/search?q=packet%20parser"));
    expect(timedOut.status).toBe(500);
    const timedOutBody = await bodyOf(timedOut);
    expect(timedOutBody.code).toBe("INTERNAL");
    expect(timedOutBody.message).toBe("Unexpected failure handling the request.");
    expectRateHeaders(timedOut);
    expectSecurityHeaders(timedOut);
    expect(JSON.stringify(timedOutBody)).not.toMatch(/\.ts\b|node_modules|stack/i);

    resetHardeningState();
    setDbOverride(db);
    const recovered = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser"),
    );
    expect(recovered.status).toBe(200);
  });
});

describe("unsafe-network input", () => {
  it("rejects SSRF-shaped queries while plain text still searches", async () => {
    const db = makeDb();
    seedMinimal(db);
    void db;

    const hostile = [
      "http://169.254.169.254/latest/meta-data",
      "https://10.0.0.5/admin",
      "http://localhost:3000/debug",
      "http://192.168.1.10/internal",
      "file:///etc/passwd",
    ];
    for (const q of hostile) {
      const response = await getSearch(
        new Request(`https://radar.test/api/v1/search?q=${encodeURIComponent(q)}`),
      );
      expect(response.status, q).toBe(400);
      expect((await bodyOf(response)).code, q).toBe("BAD_QUERY");
    }

    const benign = await getSearch(
      new Request("https://radar.test/api/v1/search?q=http%20server%20hardening%20guide"),
    );
    expect(benign.status).toBe(200);
  });
});

describe("sanitized errors", () => {
  it("keeps every error body generic with no stack traces or paths", async () => {
    const db = makeDb();
    seedMinimal(db);
    void db;

    setSearchBudgetMs(0);
    const forcedTimeout = await getSearch(
      new Request("https://radar.test/api/v1/search?q=packet%20parser"),
    );
    resetHardeningState();
    setDbOverride(db);

    const ip = "10.8.8.8";
    for (let n = 0; n < RATE_LIMIT_MAX; n += 1) checkRateLimit(ip);
    const cases: { name: string; response: Response }[] = [
      { name: "BAD_LIMIT", response: await getCves(new Request("https://radar.test/api/v1/cves?limit=999")) },
      { name: "BAD_QUERY", response: await getSearch(new Request("https://radar.test/api/v1/search?q=x")) },
      {
        name: "CVE_NOT_FOUND",
        response: await getCveById(new Request("https://radar.test/api/v1/cves/CVE-2099-9999"), {
          params: Promise.resolve({ cveId: "CVE-2099-9999" }),
        }),
      },
      {
        name: "LIST_NOT_FOUND",
        response: await getPriority(new Request("https://radar.test/api/v1/priority/nope"), {
          params: Promise.resolve({ listName: "nope" }),
        }),
      },
      {
        name: "REPLAY_UNAVAILABLE",
        response: await getReplay(
          new Request("https://radar.test/api/v1/replay?date=2020-01-01&view=highest-forecast"),
        ),
      },
      { name: "INTERNAL", response: forcedTimeout },
      { name: "RATE_LIMITED", response: await getHealth(withIp("https://radar.test/api/v1/health", ip)) },
      {
        name: "BAD_REQUEST",
        response: await getHealth(new Request(`https://radar.test/api/v1/health?pad=${"p".repeat(4200)}`)),
      },
    ];

    const allowedKeys = new Set(["code", "message", "requestId", "details", "provenance"]);
    for (const entry of cases) {
      const body = await bodyOf(entry.response);
      for (const key of Object.keys(body)) {
        expect(allowedKeys.has(key), `${entry.name} leaks key ${key}`).toBe(true);
      }
      expect(typeof body.code).toBe("string");
      expect(typeof body.message).toBe("string");
      expect(typeof body.requestId).toBe("string");
      expect(JSON.stringify(body), entry.name).not.toMatch(/\.ts\b|node_modules|\/home\/|stack|Error:/i);
      if (entry.name === "REPLAY_UNAVAILABLE") {
        const details = body.details as Record<string, unknown>;
        expect(new Set(Object.keys(details))).toEqual(new Set(["reason", "retainedFrom", "retainedTo"]));
      } else {
        expect(body.details, `${entry.name} carries no details`).toBeUndefined();
      }
    }
  });
});

describe("concurrency bound", () => {
  it("sheds load with 429 when every slot is held", async () => {
    makeDb();
    setMaxConcurrentRequests(1);
    expect(acquireConcurrencySlot()).toBe(true);

    const busy = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(busy.status).toBe(429);
    expect((await bodyOf(busy)).code).toBe("RATE_LIMITED");
    expect(Number(busy.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    expectRateHeaders(busy);

    releaseConcurrencySlot();
    const idle = await getHealth(new Request("https://radar.test/api/v1/health"));
    expect(idle.status).toBe(200);
  });
});

describe("no raw database routes", () => {
  it("exposes only GET plus preflight with no data-directory access", async () => {
    const root = path.join(__dirname, "..", "app", "api", "v1");
    const routeFiles: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name === "route.ts") routeFiles.push(full);
      }
    };
    walk(root);
    expect(routeFiles.length).toBe(10);
    for (const file of routeFiles) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/DATA_DIR|dataDir|\.db\b|openDatabase/);
    }

    const modules = [
      await import("../app/api/v1/cves/route"),
      await import("../app/api/v1/cves/[cveId]/route"),
      await import("../app/api/v1/search/route"),
      await import("../app/api/v1/priority/[listName]/route"),
      await import("../app/api/v1/radar/route"),
      await import("../app/api/v1/replay/route"),
      await import("../app/api/v1/replay/checkpoints/route"),
      await import("../app/api/v1/overview/route"),
      await import("../app/api/v1/status/route"),
      await import("../app/api/v1/health/route"),
    ];
    for (const mod of modules) {
      expect(Object.keys(mod).sort()).toEqual(["GET", "OPTIONS", "dynamic"]);
    }
  });
});
