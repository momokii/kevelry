// CVSS metrics persistence: the importer must write every CVSS metric from
// CNA and ADP containers into `cvss_metrics` (idempotently), and the
// backfill script must replay the same extraction from stored raw_json.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  extractCvssMetrics,
  importCveRevision,
} from "../src/lib/cve-import";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const tempDirs: string[] = [];
const openDbs: CveDatabase[] = [];

function makeTempDir(prefix: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function openTestDb(): CveDatabase {
  const db = openDatabase({ dataDir: makeTempDir("cvss-metrics-db-") });
  openDbs.push(db);
  return db;
}

afterEach(() => {
  while (openDbs.length > 0) {
    const db = openDbs.pop() as CveDatabase;
    try {
      db.close();
    } catch {
      // Best-effort close before directory removal.
    }
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

function git(repoDir: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: repoDir, encoding: "utf8", timeout: 30_000 });
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
    "user.email=cvss-metrics-test@example.invalid",
    "-c",
    "user.name=cvss-metrics-test",
    "commit",
    "-m",
    message,
  );
  return git(repoDir, "rev-parse", "HEAD");
}

function metricsRecordJson(
  cveId: string,
  opts: {
    cnaProvider?: string;
    cnaMetrics?: unknown[];
    adp?: Array<{ provider?: string; metrics?: unknown[] }>;
  } = {},
): string {
  const cna: Record<string, unknown> = {
    title: `Title for ${cveId}`,
    descriptions: [{ lang: "en", value: `Description for ${cveId}` }],
    providerMetadata: { shortName: opts.cnaProvider ?? "cna-test" },
  };
  if (opts.cnaMetrics !== undefined) {
    cna.metrics = opts.cnaMetrics;
  }
  const containers: Record<string, unknown> = { cna };
  if (opts.adp !== undefined) {
    containers.adp = opts.adp.map((entry) => ({
      providerMetadata: { shortName: entry.provider ?? "adp-test" },
      metrics: entry.metrics ?? [],
    }));
  }
  return JSON.stringify({
    dataType: "CVE_RECORD",
    dataVersion: "5.1",
    cveMetadata: { cveId, state: "PUBLISHED", datePublished: "2026-10-20T00:00:00.000Z" },
    containers,
  });
}

function writeRecord(repoDir: string, relPath: string, json: string): void {
  const abs = path.join(repoDir, relPath);
  mkdirSync(path.dirname(abs), { recursive: true });
  writeFileSync(abs, json);
}

function metricRows(db: CveDatabase, cveId: string): Array<Record<string, unknown>> {
  return db.handle
    .prepare(
      "SELECT cve_id, origin, provider, version, base_score, vector, source_order FROM cvss_metrics WHERE cve_id = ? ORDER BY rowid",
    )
    .all(cveId) as Array<Record<string, unknown>>;
}

describe("cvss metrics persistence (importer)", () => {
  it("writes CNA v3.1 + v4.0 and ADP v3.1 metrics with providers, versions, vectors", () => {
    const db = openTestDb();
    const repoDir = makeTempDir("cvss-metrics-repo-");
    git(repoDir, "init", "-b", "main");
    writeRecord(
      repoDir,
      "cves/2026/0xxx/CVE-2099-1001.json",
      metricsRecordJson("CVE-2099-1001", {
        cnaProvider: "cna-one",
        cnaMetrics: [
          { cvssV3_1: { version: "3.1", baseScore: 9.8, vectorString: "CVSS:3.1/AV:N/AC:L" } },
          { cvssV4_0: { version: "4.0", baseScore: 9.3, vectorString: "CVSS:4.0/AV:N/AC:L" } },
          { other: { type: "ssvc", content: { id: "x" } } },
        ],
        adp: [
          {
            provider: "adp-one",
            metrics: [
              { cvssV3_1: { version: "3.1", baseScore: 8.1, vectorString: "CVSS:3.1/AV:N/AC:H" } },
            ],
          },
        ],
      }),
    );
    writeRecord(
      repoDir,
      "cves/2026/0xxx/CVE-2099-1002.json",
      metricsRecordJson("CVE-2099-1002", { cnaMetrics: [] }),
    );
    const revA = commitAll(repoDir, "rev-a");

    const outcome = importCveRevision(db, repoDir, revA, { now: "2026-10-24T00:00:00.000Z" });
    expect(outcome.ok).toBe(true);

    const rows = metricRows(db, "CVE-2099-1001");
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({
      cve_id: "CVE-2099-1001",
      origin: "CNA",
      provider: "cna-one",
      version: "3.1",
      base_score: "9.8",
      vector: "CVSS:3.1/AV:N/AC:L",
      source_order: 0,
    });
    expect(rows[1]).toMatchObject({ origin: "CNA", version: "4.0", base_score: "9.3" });
    expect(rows[2]).toMatchObject({
      origin: "ADP",
      provider: "adp-one",
      version: "3.1",
      base_score: "8.1",
      vector: "CVSS:3.1/AV:N/AC:H",
    });
    // The ssvc "other" entry is not a CVSS metric: no row invented for it.
    expect(rows.some((row) => row.version === "other")).toBe(false);

    // A record with no metrics writes no rows.
    expect(metricRows(db, "CVE-2099-1002")).toEqual([]);
  });

  it("re-import is idempotent: changed-path refresh replaces metrics without duplicates", () => {
    const db = openTestDb();
    const repoDir = makeTempDir("cvss-metrics-repo-");
    git(repoDir, "init", "-b", "main");
    const record = (score: number): string =>
      metricsRecordJson("CVE-2099-2001", {
        cnaMetrics: [{ cvssV3_1: { version: "3.1", baseScore: score, vectorString: "CVSS:3.1/V" } }],
      });
    writeRecord(repoDir, "cves/2026/0xxx/CVE-2099-2001.json", record(9.8));
    writeRecord(
      repoDir,
      "cves/2026/0xxx/CVE-2099-2002.json",
      metricsRecordJson("CVE-2099-2002"),
    );
    const revA = commitAll(repoDir, "rev-a");
    expect(importCveRevision(db, repoDir, revA, { now: "2026-10-21T00:00:00.000Z" }).ok).toBe(true);
    expect(metricRows(db, "CVE-2099-2001")).toHaveLength(1);

    // Same revision re-import is a no-op for metrics too.
    const same = importCveRevision(db, repoDir, revA, { now: "2026-10-21T01:00:00.000Z" });
    expect(same.alreadyCurrent).toBe(true);
    expect(metricRows(db, "CVE-2099-2001")).toHaveLength(1);

    // Changed revision with a rescored metric replaces, never duplicates.
    writeRecord(repoDir, "cves/2026/0xxx/CVE-2099-2001.json", record(7.5));
    const revB = commitAll(repoDir, "rev-b");
    const outcome = importCveRevision(db, repoDir, revB, {
      changedPaths: ["cves/2026/0xxx/CVE-2099-2001.json"],
      now: "2026-10-22T00:00:00.000Z",
    });
    expect(outcome.ok).toBe(true);
    const rows = metricRows(db, "CVE-2099-2001");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ base_score: "7.5", version: "3.1", origin: "CNA" });
  });

  it("extractCvssMetrics skips unscorable entries and preserves exact score text", () => {
    const rows = extractCvssMetrics("CVE-2099-3001", {
      containers: {
        cna: {
          providerMetadata: { shortName: "cna-x" },
          metrics: [
            { cvssV3_1: { version: "3.1", baseScore: "9.80", vectorString: "V" } },
            { cvssV4_0: { version: "4.0", vectorString: "V" } },
            { other: { type: "ssvc", content: {} } },
          ],
        },
        adp: [{ metrics: [{ cvssV2_0: { version: "2.0", baseScore: 5, vectorString: "W" } }] }],
      },
    });
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ origin: "CNA", version: "3.1", baseScore: "9.80" });
    expect(rows[1]).toMatchObject({ origin: "ADP", provider: null, version: "2.0", baseScore: "5" });
    expect(extractCvssMetrics("CVE-2099-3002", { containers: {} })).toEqual([]);
    expect(extractCvssMetrics("CVE-2099-3003", null)).toEqual([]);
  });
});

describe("backfill-cvss script (no network)", () => {
  it("populates cvss_metrics from stored raw_json and is safe to re-run", () => {
    const dataDir = makeTempDir("backfill-data-");
    const db = openDatabase({ dataDir });
    const raw = metricsRecordJson("CVE-2099-9001", {
      cnaMetrics: [
        { cvssV3_1: { version: "3.1", baseScore: 9.8, vectorString: "CVSS:3.1/AV:N" } },
      ],
      adp: [{ provider: "backfill-adp", metrics: [] }],
    });
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, title, description, description_lang, source_revision, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-9001",
        "5.1",
        "PUBLISHED",
        "2026-10-20T00:00:00.000Z",
        null,
        "t",
        "d",
        "en",
        "rev",
        raw,
        "2026-10-24T00:00:00.000Z",
        "2026-10-24T00:00:00.000Z",
      );
    db.close();

    const script = path.join(process.cwd(), "scripts", "backfill-cvss.mjs");
    const run = (): { status: number | null; stdout: string; stderr: string } => {
      const result = spawnSync(process.execPath, [script], {
        env: { ...process.env, CVE_DB_FILE: path.join(dataDir, "cve.db") },
        encoding: "utf8",
        timeout: 120_000,
      });
      return { status: result.status, stdout: result.stdout as string, stderr: result.stderr as string };
    };

    const first = run();
    expect(`${first.stdout} ${first.stderr}`).toContain("backfill-done");
    expect(first.status).toBe(0);

    const check = openDatabase({ dataDir });
    openDbs.push(check);
    const rows = check.handle
      .prepare("SELECT origin, provider, version, base_score FROM cvss_metrics WHERE cve_id = ?")
      .all("CVE-2099-9001") as Array<Record<string, unknown>>;
    expect(rows).toEqual([
      { origin: "CNA", provider: "cna-test", version: "3.1", base_score: "9.8" },
    ]);

    const second = run();
    expect(second.status).toBe(0);
    const count = check.handle.prepare("SELECT COUNT(*) AS n FROM cvss_metrics").get() as {
      n: number;
    };
    expect(count.n).toBe(1);
  }, 120_000);
});
