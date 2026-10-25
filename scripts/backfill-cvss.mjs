#!/usr/bin/env node
/* global process, console */
// Backfill `cvss_metrics` from the `raw_json` already stored in `cve_records`.
//
// Volumes populated before the importer wrote metrics hold records with CVSS
// data in `raw_json` but zero rows in `cvss_metrics` (severity filters and
// the "new critical" list read that table). This script replays the same
// extraction the importer performs on ingest: no re-clone, no network, no
// git. Records stream in small keyset chunks and metrics are replaced per
// cve_id inside one transaction per chunk. Safe to re-run: output for a
// cve_id depends only on its current `raw_json`.
//
// Usage:
//   DATA_DIR=/data node scripts/backfill-cvss.mjs
//   npm run backfill:cvss
//
// Environment:
//   DATA_DIR            directory holding cve.db (default /data)
//   CVE_DB_FILE         explicit database path (overrides DATA_DIR)
//   BACKFILL_CHUNK      rows per transaction (default 2000)
//   BETTER_SQLITE3_PATH explicit path to the better-sqlite3 package

import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

const requireFromScript = createRequire(import.meta.url);

function loadBetterSqlite3() {
  const candidates = [];
  if (process.env.BETTER_SQLITE3_PATH) {
    candidates.push(process.env.BETTER_SQLITE3_PATH);
  }
  candidates.push("/app/node_modules/better-sqlite3");
  candidates.push(path.join(process.cwd(), "node_modules", "better-sqlite3"));
  let lastError = null;
  for (const candidate of candidates) {
    try {
      return requireFromScript(candidate);
    } catch (error) {
      lastError = error;
    }
  }
  try {
    return requireFromScript("better-sqlite3");
  } catch (error) {
    lastError = error;
  }
  throw new Error(
    `backfill-cvss: cannot load better-sqlite3 (tried ${candidates.join(", ")}): ${String(lastError)}`,
  );
}

const CVSS_KEY_TO_VERSION = {
  cvssV2_0: "2.0",
  cvssV3_0: "3.0",
  cvssV3_1: "3.1",
  cvssV4_0: "4.0",
};

function asRecord(value) {
  if (typeof value === "object" && value !== null) {
    return value;
  }
  return {};
}

function shortNameOf(value) {
  const record = asRecord(value);
  return typeof record.shortName === "string" && record.shortName !== ""
    ? record.shortName
    : null;
}

function baseScoreText(value) {
  if (typeof value === "string" && value !== "") {
    return value;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  return null;
}

function metricRowFromEntry(cveId, origin, provider, entry, sourceOrder) {
  const record = asRecord(entry);
  const keys = Object.keys(CVSS_KEY_TO_VERSION);
  for (const key of keys) {
    const body = record[key];
    if (typeof body !== "object" || body === null) {
      continue;
    }
    const score = baseScoreText(body.baseScore);
    if (score === null) {
      return null;
    }
    const innerVersion = body.version;
    return {
      cveId,
      origin,
      provider,
      version:
        typeof innerVersion === "string" &&
        Object.values(CVSS_KEY_TO_VERSION).includes(innerVersion)
          ? innerVersion
          : CVSS_KEY_TO_VERSION[key],
      baseScore: score,
      vector: typeof body.vectorString === "string" ? body.vectorString : "",
      sourceOrder,
    };
  }
  return null;
}

export function extractCvssMetrics(cveId, root) {
  const rows = [];
  const containers = asRecord(asRecord(root).containers);
  const cna = asRecord(containers.cna);
  const cnaProvider = shortNameOf(cna.providerMetadata);
  const cnaMetrics = Array.isArray(cna.metrics) ? cna.metrics : [];
  for (let index = 0; index < cnaMetrics.length; index += 1) {
    const row = metricRowFromEntry(cveId, "CNA", cnaProvider, cnaMetrics[index], index);
    if (row !== null) {
      rows.push(row);
    }
  }
  const adp = Array.isArray(containers.adp) ? containers.adp : [];
  for (const container of adp) {
    const adpRecord = asRecord(container);
    const provider = shortNameOf(adpRecord.providerMetadata);
    const metrics = Array.isArray(adpRecord.metrics) ? adpRecord.metrics : [];
    for (let index = 0; index < metrics.length; index += 1) {
      const row = metricRowFromEntry(cveId, "ADP", provider, metrics[index], index);
      if (row !== null) {
        rows.push(row);
      }
    }
  }
  return rows;
}

export function ensureProviderColumn(db) {
  const columns = db.prepare("PRAGMA table_info(cvss_metrics)").all();
  if (!columns.some((column) => column.name === "provider")) {
    db.exec("ALTER TABLE cvss_metrics ADD COLUMN provider TEXT NULL");
  }
}

export function resolveDbFile(env = process.env) {
  if (env.CVE_DB_FILE) {
    return env.CVE_DB_FILE;
  }
  return path.join(env.DATA_DIR ?? "/data", "cve.db");
}

export function runBackfill(options = {}) {
  const db = options.db;
  const chunkSize = options.chunkSize ?? 2000;
  const onProgress = options.onProgress;
  if (!db) {
    throw new Error("runBackfill requires an open better-sqlite3 database handle.");
  }
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
    throw new Error(`runBackfill requires a positive chunk size, got ${chunkSize}.`);
  }
  ensureProviderColumn(db);
  db.exec("PRAGMA busy_timeout = 60000");

  const totalRow = db.prepare("SELECT COUNT(*) AS n FROM cve_records").get();
  const total = totalRow.n;
  const selectChunk = db.prepare(
    "SELECT cve_id, raw_json FROM cve_records WHERE cve_id > ? ORDER BY cve_id ASC LIMIT ?",
  );
  const deleteById = db.prepare("DELETE FROM cvss_metrics WHERE cve_id = ?");
  const insertMetric = db.prepare(
    "INSERT INTO cvss_metrics (cve_id, origin, provider, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const writeChunk = db.transaction((rows) => {
    for (const row of rows) {
      let parsed = null;
      try {
        parsed = JSON.parse(row.raw_json);
      } catch {
        continue;
      }
      const metrics = extractCvssMetrics(row.cve_id, parsed);
      deleteById.run(row.cve_id);
      for (const metric of metrics) {
        insertMetric.run(
          metric.cveId,
          metric.origin,
          metric.provider,
          metric.version,
          metric.baseScore,
          metric.vector,
          metric.sourceOrder,
        );
      }
    }
  });

  let scanned = 0;
  let lastId = "";
  for (;;) {
    const rows = selectChunk.all(lastId, chunkSize);
    if (rows.length === 0) {
      break;
    }
    writeChunk(rows);
    for (const row of rows) {
      lastId = row.cve_id;
      scanned += 1;
      if (scanned % 50000 === 0 && onProgress) {
        onProgress({ scanned, total });
      }
    }
  }
  const withMetrics = db.prepare("SELECT COUNT(DISTINCT cve_id) AS n FROM cvss_metrics").get().n;
  const metricRows = db.prepare("SELECT COUNT(*) AS n FROM cvss_metrics").get().n;
  return { scanned, total, withMetrics, metricRows };
}

function main() {
  const Database = loadBetterSqlite3();
  const dbFile = resolveDbFile();
  const chunkSize = Number(process.env.BACKFILL_CHUNK ?? 2000);
  const db = new Database(dbFile);
  try {
    const startedAt = Date.now();
    console.log(JSON.stringify({ event: "backfill-start", dbFile, chunkSize }));
    const summary = runBackfill({
      db,
      chunkSize,
      onProgress: ({ scanned, total }) =>
        console.log(JSON.stringify({ event: "backfill-progress", scanned, total })),
    });
    console.log(
      JSON.stringify({ event: "backfill-done", ...summary, durationMs: Date.now() - startedAt }),
    );
  } finally {
    db.close();
  }
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invoked && import.meta.url === pathToFileURL(invoked).href) {
  main();
}

