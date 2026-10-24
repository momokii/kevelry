// New-test justification (plan todo 30): import, search, and storage budgets
// are the release gate for operational feasibility (GAP-6), so this suite is
// the reproducible benchmark harness itself: it builds a pinned synthetic
// corpus (no network), times the real full-import and incremental-import
// paths, times the real KEV/EPSS importers, reports join/metric coverage,
// times a recorded 50-query search mix at concurrency 1 and 10, pins the
// /api/v1/cves and /api/v1/replay endpoints with live handler calls, measures
// WAL/storage growth and the 30-checkpoint retained-history cost, reruns the
// mix on a reopened handle for the cold-cache variance check, writes the raw
// numbers to .omo/evidence/task-30-cve-change-radar.results.json, and asserts
// every approved budget (full < 120 min, incremental < 30 min, p50 < 200 ms
// and p95 < 1000 ms at 10 concurrent, WAL < 2x DB). A budget miss fails this
// suite with the measured number; budgets are never widened here.
//
// Scale honesty: the full upstream corpus (394,803-row EPSS shape reference,
// 1,756-entry KEV shape reference, whole CVE List V5) is not vendored into
// this repo, so the harness measures a deterministic 2,000-record scaled
// fixture through the unmodified production importers and query services.
// Absolute durations therefore describe this machine and fixture only; the
// committed verdicts are PASS/FAIL of the measured numbers against the
// budgets on this machine, never universal performance claims.

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { arch, cpus, platform, tmpdir, totalmem } from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { afterEach, describe, expect, it } from "vitest";

import { GET as getCves } from "../app/api/v1/cves/route";
import { GET as getCheckpoints } from "../app/api/v1/replay/checkpoints/route";
import { GET as getReplay } from "../app/api/v1/replay/route";
import {
  RANKING_POLICY_VERSION,
  resetDbOverride,
  resetHardeningState,
  setDbOverride,
} from "../app/api/v1/_lib/shared";
import { type CveDatabase, openDatabase } from "../src/lib/db";
import { diffChangedPaths, importCveRevision } from "../src/lib/cve-import";
import { importEpssCsv } from "../src/lib/epss-import";
import { importKevCatalog } from "../src/lib/kev-import";
import { RADAR_POLICY_VERSION, writeCheckpoint } from "../src/lib/radar";
import { searchCves, type SearchFilters } from "../src/lib/search";

// ---------------------------------------------------------------------------
// Budgets (approved in .omo/plans/cve-change-radar.md todo 30; ms units).
// ---------------------------------------------------------------------------

const FULL_IMPORT_BUDGET_MS = 120 * 60 * 1000;
const INCREMENTAL_BUDGET_MS = 30 * 60 * 1000;
const SEARCH_P50_BUDGET_MS = 200;
const SEARCH_P95_BUDGET_MS = 1000;
const WAL_RATIO_BUDGET = 2;
const COLD_CACHE_TOLERANCE = 0.2;

// ---------------------------------------------------------------------------
// Deterministic fixture scale.
// ---------------------------------------------------------------------------

const RECORDS_PER_YEAR = 1000;
const BENCH_YEARS = [2024, 2025] as const;
const EPSS_SCORE_DATE = "2026-10-23";
const EPSS_MODEL = "v2026.06.15";
const KEV_CATALOG_DATE = "2026-10-24T00:00:00.000Z";
const KEV_CATALOG_VERSION = "2026.10.24-bench";
const RESULTS_PATH = path.join(
  process.cwd(),
  ".omo",
  "evidence",
  "task-30-cve-change-radar.results.json",
);

const KEYWORDS = [
  "buffer overflow",
  "SQL injection",
  "cross-site scripting",
  "insecure deserialization",
  "privilege escalation",
  "path traversal",
  "server-side request forgery",
  "use-after-free",
] as const;

const SCORE_CYCLE = ["2.5", "4.3", "5.4", "6.5", "7.2", "8.1", "9.1", "9.8", "3.9", "7.5"] as const;

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function openBenchDb(): { db: CveDatabase; dir: string } {
  const dir = makeTempDir("cve-bench-db-");
  const db = openDatabase({ dataDir: dir });
  openDbs.push(db);
  return { db, dir };
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

function git(repoDir: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 60_000 });
  if (result.error !== undefined) {
    throw new Error(`git ${args.join(" ")} failed: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited ${String(result.status)}: ${result.stderr}`);
  }
  return (result.stdout as string).trim();
}

function commitAll(repoDir: string, message: string): string {
  git(repoDir, "add", "-A");
  git(
    repoDir,
    "-c",
    "user.email=cve-bench@example.invalid",
    "-c",
    "user.name=cve-bench",
    "commit",
    "-m",
    message,
  );
  return git(repoDir, "rev-parse", "HEAD");
}

interface BenchRecord {
  index: number;
  cveId: string;
  relPath: string;
  datePublished: string | null;
  description: string;
  lang: string;
}

function benchId(year: number, sequence: number): string {
  return `CVE-${year}-${String(sequence).padStart(4, "0")}`;
}

function recordPath(year: number, sequence: number): string {
  const bucket = `${String(Math.floor((sequence - 1) / 100))}xxx`;
  return `cves/${year}/${bucket}/${benchId(year, sequence)}.json`;
}

function publishedStamp(index: number, year: number): string | null {
  if (index % 20 === 19) return null;
  const base = Date.parse(`${year}-01-01T00:00:00.000Z`);
  const dayMs = 24 * 60 * 60 * 1000;
  return new Date(base + index * 7 * dayMs).toISOString();
}

function descriptionFor(index: number, cveId: string): string {
  const keyword = KEYWORDS[index % KEYWORDS.length] as string;
  const component = `component-${index % 64}`;
  const vendor = `vendor-${index % 32}`;
  return (
    `A ${keyword} vulnerability was discovered in ${component} by ${vendor}. ` +
    `A remote attacker can exploit this flaw to compromise confidentiality, integrity, and availability ` +
    `of affected deployments when processing crafted input. Mitigation: apply the vendor patch and ` +
    `restrict network exposure until updated. Reference token seq-${cveId}.`
  );
}

function recordJson(record: BenchRecord, state: "PUBLISHED" | "REJECTED" = "PUBLISHED"): string {
  const meta: Record<string, string> = { cveId: record.cveId, dataVersion: "5.1", state };
  if (record.datePublished !== null) {
    meta.datePublished = record.datePublished;
    meta.dateUpdated = record.datePublished;
  }
  return JSON.stringify({
    dataType: "CVE_RECORD",
    dataVersion: "5.1",
    cveMetadata: meta,
    containers: {
      cna: {
        title: `Bench title ${record.cveId} (${KEYWORDS[record.index % KEYWORDS.length] as string})`,
        descriptions: [{ lang: record.lang, value: record.description }],
      },
    },
  });
}

function buildCorpus(): BenchRecord[] {
  const records: BenchRecord[] = [];
  let index = 0;
  for (const year of BENCH_YEARS) {
    for (let sequence = 1; sequence <= RECORDS_PER_YEAR; sequence += 1) {
      const cveId = benchId(year, sequence);
      records.push({
        index,
        cveId,
        relPath: recordPath(year, sequence),
        datePublished: publishedStamp(index, year),
        description: descriptionFor(index, cveId),
        lang: index % 25 === 24 ? "fr" : "en",
      });
      index += 1;
    }
  }
  return records;
}

function writeRecordFile(repoDir: string, relPath: string, json: string): void {
  const abs = path.join(repoDir, relPath);
  mkdirSync(path.dirname(abs), { recursive: true });
  writeFileSync(abs, json);
}

function percentileDesc(values: number[], percentile: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.min(sorted.length - 1, Math.floor((percentile / 100) * sorted.length));
  return sorted[rank] as number;
}

function fileBytes(filePath: string): number {
  try {
    return statSync(filePath).size;
  } catch {
    return 0;
  }
}

function dbFiles(dir: string): { dbBytes: number; walBytes: number; shmBytes: number } {
  const base = path.join(dir, "cve.db");
  return { dbBytes: fileBytes(base), walBytes: fileBytes(`${base}-wal`), shmBytes: fileBytes(`${base}-shm`) };
}

function epssValue(index: number, salt: number): string {
  return (((index * 7919 + salt * 104729) % 100000) / 100000).toFixed(5);
}

function buildSearchMix(): { name: string; filters: SearchFilters }[] {
  const mix: { name: string; filters: SearchFilters }[] = [];
  const exactIds = [
    "CVE-2024-0501",
    "CVE-2024-0999",
    "CVE-2025-0001",
    "CVE-2025-0500",
    "CVE-2025-1000",
    "CVE-2024-0009",
    "CVE-1999-0001",
    "CVE-2024-9999",
  ];
  for (const id of exactIds) mix.push({ name: `id:${id}`, filters: { q: id } });
  const prefixes = [
    "CVE-2024-0",
    "cve-2025-10",
    "CVE-202",
    "CVE",
    "CVE-2025-00",
    "cve-2024-99",
    "CVE-2025-1",
    "CVE-2024-5",
  ];
  for (const prefix of prefixes) mix.push({ name: `prefix:${prefix}`, filters: { q: prefix } });
  const texts = [
    "buffer overflow",
    "sql injection",
    "cross-site scripting",
    "privilege escalation",
    "path traversal",
    "use-after-free",
    "deserialization",
    "request forgery",
    "component-7",
    "vendor-3",
    "seq-CVE-2025-0420",
    "remote attacker crafted input",
    "confidentiality integrity availability",
    "restrict network exposure",
  ];
  for (const text of texts) mix.push({ name: `text:${text}`, filters: { q: text } });
  mix.push({ name: "filter:critical", filters: { severity: ["critical"] } });
  mix.push({ name: "filter:high-critical", filters: { severity: ["high", "critical"] } });
  mix.push({ name: "filter:kev-only", filters: { kev: "only" } });
  mix.push({ name: "filter:epss-present", filters: { epss: "present" } });
  mix.push({ name: "filter:epss-absent", filters: { epss: "absent" } });
  mix.push({
    name: "filter:date-2024",
    filters: { dateStart: "2024-01-01T00:00:00.000Z", dateEnd: "2025-01-01T00:00:00.000Z" },
  });
  mix.push({
    name: "filter:combo",
    filters: { q: "overflow", severity: ["high", "critical"], kev: "all", limit: 10 },
  });
  mix.push({ name: "filter:unknown-band", filters: { severity: ["unknown"] } });
  const hostile = [
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../etc/passwd",
    "!!!",
    '"unbalanced quote',
    "CVE-2024-0009' --",
  ];
  for (const text of hostile) mix.push({ name: `hostile:${text.slice(0, 16)}`, filters: { q: text } });
  mix.push({ name: "page:empty-q", filters: {} });
  mix.push({ name: "page:limit-1", filters: { limit: 1 } });
  mix.push({ name: "page:limit-5", filters: { q: "vulnerability", limit: 5 } });
  mix.push({ name: "page:limit-50", filters: { q: "vulnerability", limit: 50 } });
  mix.push({ name: "page:limit-100", filters: { q: "vulnerability", limit: 100 } });
  mix.push({ name: "page:kev-excluded", filters: { kev: "excluded", limit: 5 } });
  expect(mix.length).toBe(50);
  return mix;
}

describe("cve change radar benchmarks (todo 30)", () => {
  it(
    "measures import, search, and storage against the approved budgets",
    { timeout: 600_000 },
    async () => {
      const corpus = buildCorpus();
      expect(corpus.length).toBe(RECORDS_PER_YEAR * BENCH_YEARS.length);

      // -- Fixture git repo: revA is the full corpus. ---------------------
      const repoDir = makeTempDir("cve-bench-repo-");
      git(repoDir, "init", "-b", "main");
      for (const record of corpus) {
        writeRecordFile(repoDir, record.relPath, recordJson(record));
      }
      writeRecordFile(repoDir, "cves/delta.json", "delta manifest, not a record");
      const revA = commitAll(repoDir, "bench rev-a: full corpus");

      const { db, dir } = openBenchDb();
      const startedFull = performance.now();
      const fullOutcome = importCveRevision(db, repoDir, revA, {
        now: "2026-10-24T00:00:00.000Z",
      });
      const fullImportMs = performance.now() - startedFull;
      expect(fullOutcome.ok).toBe(true);
      expect(fullOutcome.reconciledFull).toBe(true);
      expect(fullOutcome.quarantined).toEqual([]);
      const publishedAfterFull = db.handle
        .prepare("SELECT COUNT(*) AS n FROM cve_records WHERE state = ?")
        .get("PUBLISHED") as { n: number };
      expect(publishedAfterFull.n).toBe(corpus.length);

      // -- revB: 40 changed + 15 added + 8 deleted + 1 rejected. ----------
      const changedIdx = new Set<number>();
      for (let index = 100; index < 140; index += 1) changedIdx.add(index);
      const addedRecords: BenchRecord[] = [];
      for (let sequence = RECORDS_PER_YEAR + 1; sequence <= RECORDS_PER_YEAR + 15; sequence += 1) {
        const cveId = benchId(2025, sequence);
        addedRecords.push({
          index: corpus.length + addedRecords.length,
          cveId,
          relPath: recordPath(2025, sequence),
          datePublished: "2026-10-20T00:00:00.000Z",
          description: descriptionFor(corpus.length + addedRecords.length, cveId),
          lang: "en",
        });
      }
      const deletedIds = corpus.slice(0, 8).map((record) => record.cveId);
      const rejectedId = corpus[200] as BenchRecord;

      for (const index of changedIdx) {
        const record = corpus[index] as BenchRecord;
        writeRecordFile(
          repoDir,
          record.relPath,
          recordJson({ ...record, description: `${record.description} Corrected impact statement.` }),
        );
      }
      for (const record of addedRecords) {
        writeRecordFile(repoDir, record.relPath, recordJson(record));
      }
      for (const cveId of deletedIds) {
        const record = corpus.find((entry) => entry.cveId === cveId) as BenchRecord;
        git(repoDir, "rm", "-q", record.relPath);
      }
      writeRecordFile(repoDir, rejectedId.relPath, recordJson(rejectedId, "REJECTED"));
      const revB = commitAll(repoDir, "bench rev-b: incremental delta");

      const changedPaths = diffChangedPaths(repoDir, revA, revB);
      expect(changedPaths.length).toBe(40 + 15 + 8 + 1);
      const startedIncr = performance.now();
      const incrOutcome = importCveRevision(db, repoDir, revB, {
        changedPaths,
        now: "2026-10-24T01:00:00.000Z",
      });
      const incrementalMs = performance.now() - startedIncr;
      expect(incrOutcome.ok).toBe(true);
      expect(incrOutcome.reconciledFull).toBe(false);
      expect(incrOutcome.transitions.added.length).toBe(15);
      expect(incrOutcome.transitions.deleted.length).toBe(8);
      expect(incrOutcome.transitions.rejected).toContain(rejectedId.cveId);
      expect(incrOutcome.transitions.changed.length).toBeGreaterThanOrEqual(40);

      // -- Metrics seed (70% coverage, CNA versions incl. legacy 2.0). ----
      const liveIds = (
        db.handle.prepare("SELECT cve_id FROM cve_records WHERE state = ?").all("PUBLISHED") as Array<{
          cve_id: string;
        }>
      ).map((row) => row.cve_id);
      db.runBoundedWrite(() => {
        const insert = db.handle.prepare(
          "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
        );
        for (const [position, cveId] of liveIds.entries()) {
          if (position % 10 >= 7) continue;
          insert.run(
            cveId,
            "CNA",
            position % 10 === 6 ? "2.0" : "3.1",
            SCORE_CYCLE[position % SCORE_CYCLE.length] as string,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            0,
          );
        }
      });

      // -- KEV snapshot import (150 matched + 5 reported unmatched). ------
      const kevIds = liveIds.filter((id) => id >= "CVE-2025-0001").slice(0, 150);
      expect(kevIds.length).toBe(150);
      const kevUnmatched = [
        "CVE-2026-90001",
        "CVE-2026-90002",
        "CVE-2026-90003",
        "CVE-2026-90004",
        "CVE-2026-90005",
      ];
      const startedKev = performance.now();
      const kevResult = importKevCatalog(
        db,
        {
          catalogVersion: KEV_CATALOG_VERSION,
          dateReleased: KEV_CATALOG_DATE,
          count: kevIds.length + kevUnmatched.length,
          vulnerabilities: [...kevIds, ...kevUnmatched].map((cveId) => ({
            cveID: cveId,
            dateAdded: "2026-10-18",
            vendorProject: "Bench Vendor",
            product: "Bench Product",
          })),
        },
        { now: "2026-10-24T02:00:00.000Z" },
      );
      const kevImportMs = performance.now() - startedKev;
      expect(kevResult.total).toBe(155);
      expect(kevResult.unmatched.length).toBe(5);

      // -- EPSS daily import (70% matched + 10 reported unmatched). --------
      const epssIds = liveIds.filter((_, position) => position % 10 < 7);
      const epssUnmatched = Array.from({ length: 10 }, (_, i) => `CVE-2026-91${String(i).padStart(3, "0")}`);
      const epssCsv = [
        `#model_version:${EPSS_MODEL},score_date:${EPSS_SCORE_DATE}T12:00:28Z`,
        "cve,epss,percentile",
        ...epssIds.map(
          (cveId, position) => `${cveId},${epssValue(position, 1)},${epssValue(position, 2)}`,
        ),
        ...epssUnmatched.map(
          (cveId, position) => `${cveId},${epssValue(position, 3)},${epssValue(position, 4)}`,
        ),
      ].join("\n");
      const startedEpss = performance.now();
      const epssResult = importEpssCsv(db, epssCsv);
      const epssImportMs = performance.now() - startedEpss;
      expect(epssResult.rowCount).toBe(epssIds.length + epssUnmatched.length);
      expect(epssResult.unmatched.length).toBe(10);

      // -- Join/metric coverage. -------------------------------------------
      const coverage = db.handle
        .prepare(
          "SELECT (SELECT COUNT(*) FROM cve_records WHERE state = 'PUBLISHED') AS published, " +
            "(SELECT COUNT(DISTINCT cve_id) FROM cvss_metrics) AS withMetrics, " +
            "(SELECT COUNT(*) FROM kev_entries) AS kevMembers, " +
            "(SELECT COUNT(*) FROM epss_daily WHERE score_date = ?) AS epssKnown",
        )
        .get(EPSS_SCORE_DATE) as {
        published: number;
        withMetrics: number;
        kevMembers: number;
        epssKnown: number;
      };
      expect(coverage.published).toBeGreaterThan(0);
      expect(coverage.withMetrics).toBeGreaterThan(0);
      expect(coverage.kevMembers).toBe(155);
      expect(coverage.epssKnown).toBe(epssIds.length + epssUnmatched.length);

      // -- Search mix: warmup, sequential, 10-concurrent, cold cache. ------
      const mix = buildSearchMix();
      for (const entry of mix) {
        searchCves(db, entry.filters);
      }

      const runMix = (): number[] => {
        const latencies: number[] = [];
        for (const entry of mix) {
          const start = performance.now();
          searchCves(db, entry.filters);
          latencies.push(performance.now() - start);
        }
        return latencies;
      };

      const seqLatencies = runMix();
      const seqP50 = percentileDesc(seqLatencies, 50);
      const seqP95 = percentileDesc(seqLatencies, 95);

      const startedConc = performance.now();
      const concLatenciesNested = await Promise.all(
        Array.from({ length: 10 }, () => Promise.resolve().then(() => runMix())),
      );
      const concWallMs = performance.now() - startedConc;
      const concLatencies = concLatenciesNested.flat();
      expect(concLatencies.length).toBe(500);
      const concP50 = percentileDesc(concLatencies, 50);
      const concP95 = percentileDesc(concLatencies, 95);

      // -- Storage: peak WAL before the explicit checkpoint. ---------------
      const preCheckpoint = dbFiles(dir);
      const preCheckpointWalRatio =
        preCheckpoint.dbBytes === 0 ? 0 : preCheckpoint.walBytes / preCheckpoint.dbBytes;
      const checkpoint = db.checkpointStatus();
      const postCheckpoint = dbFiles(dir);

      // -- Retained history: 30 daily checkpoints, cost recorded. ----------
      const historySizeBefore = postCheckpoint.dbBytes;
      const startedHistory = performance.now();
      const checkpointDates: string[] = [];
      for (let ago = 29; ago >= 0; ago -= 1) {
        const day = new Date(Date.parse("2026-10-24T00:00:00.000Z") - ago * 24 * 60 * 60 * 1000);
        checkpointDates.push(day.toISOString().slice(0, 10));
      }
      for (const checkpointDate of checkpointDates) {
        writeCheckpoint(db, {
          checkpointDate,
          observedAt: `${checkpointDate}T12:00:00.000Z`,
          sourcePins: {
            cveRevision: revB,
            kevCatalogDate: "2026-10-24",
            epssScoreDate: EPSS_SCORE_DATE,
            epssModelVersion: EPSS_MODEL,
          },
        });
      }
      const historyMs = performance.now() - startedHistory;
      const historyFiles = dbFiles(dir);
      const historyDeltaBytes = historyFiles.dbBytes - historySizeBefore;

      // -- Pinned API endpoints: /api/v1/cves and /api/v1/replay. ----------
      resetHardeningState();
      setDbOverride(db);
      const apiPins: Array<{ endpoint: string; status: number; ms: number }> = [];
      try {
        const calls: Array<[string, string]> = [
          ["cves-list", "https://radar.test/api/v1/cves?limit=20"],
          ["cves-kev", "https://radar.test/api/v1/cves?limit=5&kev=listed"],
          ["search", "https://radar.test/api/v1/search?q=buffer%20overflow&limit=5"],
          ["replay", `https://radar.test/api/v1/replay?date=2026-10-24&view=known-exploited&limit=5`],
          ["checkpoints", "https://radar.test/api/v1/replay/checkpoints"],
        ];
        for (const [label, url] of calls) {
          const start = performance.now();
          let response: Response;
          if (label === "replay") {
            response = await getReplay(new Request(url));
          } else if (label === "checkpoints") {
            response = await getCheckpoints(new Request(url));
          } else {
            response = await getCves(new Request(url));
          }
          apiPins.push({ endpoint: url, status: response.status, ms: performance.now() - start });
          await response.text();
        }
      } finally {
        resetDbOverride();
      }
      const replayPin = apiPins.find((pin) => pin.endpoint.includes("/api/v1/replay?")) as {
        status: number;
      };
      expect(apiPins.every((pin) => pin.status === 200)).toBe(true);
      expect(replayPin.status).toBe(200);

      // -- Cold-cache rerun on a reopened handle. ---------------------------
      db.close();
      const coldDb = openDatabase({ dataDir: dir });
      openDbs.push(coldDb);
      const coldLatencies: number[] = [];
      for (const entry of mix) {
        const start = performance.now();
        searchCves(coldDb, entry.filters);
        coldLatencies.push(performance.now() - start);
      }
      const coldP50 = percentileDesc(coldLatencies, 50);
      const coldP95 = percentileDesc(coldLatencies, 95);
      const drift = (cold: number, warm: number): number =>
        warm === 0 ? (cold === 0 ? 0 : 1) : Math.abs(cold - warm) / warm;
      const coldP50Drift = drift(coldP50, concP50);
      const coldP95Drift = drift(coldP95, concP95);
      const coldCacheFlagged = coldP50Drift > COLD_CACHE_TOLERANCE || coldP95Drift > COLD_CACHE_TOLERANCE;

      // -- Verdicts (budgets never widened; a miss fails with numbers). ----
      const verdicts = {
        fullImport: fullImportMs < FULL_IMPORT_BUDGET_MS ? "PASS" : "FAIL",
        incremental: incrementalMs < INCREMENTAL_BUDGET_MS ? "PASS" : "FAIL",
        searchP50: concP50 < SEARCH_P50_BUDGET_MS ? "PASS" : "FAIL",
        searchP95: concP95 < SEARCH_P95_BUDGET_MS ? "PASS" : "FAIL",
        walRatio: preCheckpointWalRatio < WAL_RATIO_BUDGET ? "PASS" : "FAIL",
        historyRecorded: "PASS" as const,
      };

      const results = {
        generatedAt: new Date().toISOString(),
        machine: {
          platform: platform(),
          arch: arch(),
          cpuModel: cpus()[0]?.model ?? "unknown",
          cpuCount: cpus().length,
          totalMemBytes: totalmem(),
          node: process.version,
        },
        dataset: {
          cveFixtureRecords: corpus.length + addedRecords.length,
          cveRevisionFull: revA,
          cveRevisionIncremental: revB,
          incrementalTransitions: incrOutcome.transitions,
          epssShapeReference: "2026-10-24 structural fixture, 394,803 rows (shape reference only)",
          epssBenchRows: epssResult.rowCount,
          epssScoreDate: EPSS_SCORE_DATE,
          epssModelVersion: EPSS_MODEL,
          kevShapeReference: "1,756-entry declared/actual/unique match (shape reference only)",
          kevBenchEntries: kevResult.total,
          kevCatalogVersion: KEV_CATALOG_VERSION,
          kevCatalogDate: KEV_CATALOG_DATE,
          kevUnmatchedReported: kevResult.unmatched,
          epssUnmatchedReported: epssResult.unmatched,
          rankingPolicyVersion: RANKING_POLICY_VERSION,
          radarPolicyVersion: RADAR_POLICY_VERSION,
          endpointsPinned: ["/api/v1/cves", "/api/v1/replay"],
          apiPins,
          reproducibility:
            "deterministic synthetic fixture (index-derived IDs, dates, scores); no network; no Math.random",
        },
        measurements: {
          fullImportMs,
          incrementalMs,
          kevImportMs,
          epssImportMs,
          coverage,
          search: {
            mixSize: mix.length,
            sequential: { p50Ms: seqP50, p95Ms: seqP95, maxMs: Math.max(...seqLatencies) },
            concurrent10: {
              samples: concLatencies.length,
              wallMs: concWallMs,
              p50Ms: concP50,
              p95Ms: concP95,
              maxMs: Math.max(...concLatencies),
            },
            coldCache: {
              p50Ms: coldP50,
              p95Ms: coldP95,
              p50Drift: coldP50Drift,
              p95Drift: coldP95Drift,
              flagged: coldCacheFlagged,
            },
          },
          storage: {
            preCheckpointWalBytes: preCheckpoint.walBytes,
            preCheckpointDbBytes: preCheckpoint.dbBytes,
            walRatio: preCheckpointWalRatio,
            postCheckpoint,
            checkpointBusy: checkpoint.busy,
          },
          history: {
            checkpointsWritten: checkpointDates.length,
            historyMs,
            deltaBytes: historyDeltaBytes,
            perCheckpointBytes: historyDeltaBytes / checkpointDates.length,
            finalDbBytes: historyFiles.dbBytes,
          },
        },
        budgets: {
          fullImportMs: { budget: FULL_IMPORT_BUDGET_MS, measured: fullImportMs, verdict: verdicts.fullImport },
          incrementalMs: { budget: INCREMENTAL_BUDGET_MS, measured: incrementalMs, verdict: verdicts.incremental },
          searchP50Ms: { budget: SEARCH_P50_BUDGET_MS, measured: concP50, verdict: verdicts.searchP50 },
          searchP95Ms: { budget: SEARCH_P95_BUDGET_MS, measured: concP95, verdict: verdicts.searchP95 },
          walRatio: { budget: WAL_RATIO_BUDGET, measured: preCheckpointWalRatio, verdict: verdicts.walRatio },
          historyCostBytes: { budget: "recorded (no cap)", measured: historyDeltaBytes, verdict: verdicts.historyRecorded },
        },
      };

      mkdirSync(path.dirname(RESULTS_PATH), { recursive: true });
      writeFileSync(RESULTS_PATH, `${JSON.stringify(results, null, 2)}\n`);
      expect(existsSync(RESULTS_PATH)).toBe(true);
      const roundTripped = JSON.parse(readFileSync(RESULTS_PATH, "utf8")) as typeof results;
      expect(roundTripped.budgets.fullImportMs.verdict).toBe("PASS");

      expect(fullImportMs).toBeLessThan(FULL_IMPORT_BUDGET_MS);
      expect(incrementalMs).toBeLessThan(INCREMENTAL_BUDGET_MS);
      expect(concP50).toBeLessThan(SEARCH_P50_BUDGET_MS);
      expect(concP95).toBeLessThan(SEARCH_P95_BUDGET_MS);
      expect(preCheckpointWalRatio).toBeLessThan(WAL_RATIO_BUDGET);
    },
  );
});
