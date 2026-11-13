// CISA Vulnrichment → SSVC decision points (v3 headline feature).
//
// Source: github.com/cisagov/vulnrichment (CC0-1.0, ~380 MB). Each record is
// `YYYY/<prefix>xxx/CVE-….json` and may carry an ADP container titled
// "CISA ADP Vulnrichment" whose `metrics[].other` entry of type `ssvc` holds
// CISA's published decision points:
//
//   Exploitation:      none | poc | active
//   Automatable:       yes | no
//   Technical Impact:  partial | total
//
// We store those three verbatim and never fold them into a score of our own.
// Coverage is partial by design: a CVE without an SSVC block stays absent
// (unknown), which is a fact about the source, not a missing feature.
//
// Ingest scope is the KEV-listed cohort: the priority views are KEV-based, the
// walk can skip every file whose basename is not wanted without reading it,
// and the whole cycle stays in seconds rather than minutes.

import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";

import type { CveDatabase } from "./db";
import {
  buildCloneArgs,
  buildFetchArgs,
  getCacheSizeBytes,
  isValidGitRepo,
  runGit,
} from "./cve-import";

export const VULNRICHMENT_REPO_URL = "https://github.com/cisagov/vulnrichment.git";
export const VULNRICHMENT_REVISION = "develop";
export const VULNRICHMENT_CACHE_DIRNAME = "vulnrichment-repo";
export const VULNRICHMENT_DEFAULT_TIMEOUT_MS = 60 * 60 * 1000;

export type SsvcExploitation = "none" | "poc" | "active";
export type SsvcAutomatable = "yes" | "no";
export type SsvcTechnicalImpact = "partial" | "total";

export interface SsvcDecision {
  exploitation: SsvcExploitation;
  automatable: SsvcAutomatable;
  technicalImpact: SsvcTechnicalImpact;
  version: string | null;
  timestamp: string | null;
}

export class SsvcImportError extends Error {
  readonly name = "SsvcImportError";
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
}

function pickOption(options: unknown, key: string): string | null {
  if (!Array.isArray(options)) return null;
  for (const entry of options) {
    const row = asRecord(entry);
    if (row === null) continue;
    const value = row[key];
    if (typeof value === "string") return value.toLowerCase();
  }
  return null;
}

/**
 * Extract SSVC decision points from one vulnrichment record. Returns null when
 * the record publishes no SSVC block; throws SsvcImportError only when a block
 * exists but is malformed, so a bad record cannot silently look "unknown".
 */
export function parseSsvcRecord(root: unknown): SsvcDecision | null {
  const doc = asRecord(root);
  if (doc === null) throw new SsvcImportError("vulnrichment record must be an object");
  const containers = asRecord(doc.containers);
  const adp = containers?.adp;
  if (!Array.isArray(adp)) return null;

  for (const entry of adp) {
    const container = asRecord(entry);
    if (container === null) continue;
    const title = typeof container.title === "string" ? container.title : "";
    if (!title.toLowerCase().includes("vulnrichment")) continue;
    const metrics = container.metrics;
    if (!Array.isArray(metrics)) continue;
    for (const metric of metrics) {
      const row = asRecord(metric);
      const other = asRecord(row?.other);
      if (other === null || other.type !== "ssvc") continue;
      const content = asRecord(other.content);
      if (content === null) continue;
      const exploitation = pickOption(content.options, "Exploitation");
      const automatable = pickOption(content.options, "Automatable");
      const impact = pickOption(content.options, "Technical Impact");
      if (exploitation === null || automatable === null || impact === null) {
        throw new SsvcImportError(
          "SSVC block is missing one of Exploitation/Automatable/Technical Impact",
        );
      }
      if (exploitation !== "none" && exploitation !== "poc" && exploitation !== "active") {
        throw new SsvcImportError(`unknown SSVC exploitation value "${exploitation}"`);
      }
      if (automatable !== "yes" && automatable !== "no") {
        throw new SsvcImportError(`unknown SSVC automatable value "${automatable}"`);
      }
      if (impact !== "partial" && impact !== "total") {
        throw new SsvcImportError(`unknown SSVC technical impact value "${impact}"`);
      }
      return {
        exploitation,
        automatable,
        technicalImpact: impact,
        version: typeof content.version === "string" ? content.version : null,
        timestamp: typeof content.timestamp === "string" ? content.timestamp : null,
      };
    }
  }
  return null;
}

/**
 * Walk the checkout and return only the files whose CVE id is wanted. The
 * filename carries the id, so unwanted records are never opened.
 */
export function listSsvcFiles(checkoutDir: string, wanted: ReadonlySet<string>): string[] {
  const out: string[] = [];
  if (wanted.size === 0) return out;
  for (const year of readdirSync(checkoutDir, { withFileTypes: true })) {
    if (!year.isDirectory() || !/^[0-9]{4}$/.test(year.name)) continue;
    const yearDir = path.join(checkoutDir, year.name);
    for (const bucket of readdirSync(yearDir, { withFileTypes: true })) {
      if (!bucket.isDirectory()) continue;
      const bucketDir = path.join(yearDir, bucket.name);
      for (const file of readdirSync(bucketDir, { withFileTypes: true })) {
        if (!file.isFile() || !file.name.endsWith(".json")) continue;
        const id = file.name.slice(0, -".json".length);
        if (!wanted.has(id)) continue;
        out.push(`${year.name}/${bucket.name}/${file.name}`);
      }
    }
  }
  return out;
}

export interface SsvcImportResult {
  ok: true;
  catalogDate: string;
  total: number;
  parsed: number;
  absent: number;
  invalid: string[];
  revision: string | null;
}

export interface SsvcImportOptions {
  /** Checkout directory holding the repository contents. */
  checkoutDir: string;
  /** CVE ids to look for (the KEV cohort). */
  wanted: ReadonlySet<string>;
  /** Pinned revision label recorded with the rows. */
  revision?: string | null;
  /** ISO instant used as catalog_date/recorded_at. */
  now?: string;
}

/**
 * Import SSVC rows for the wanted ids. Existing rows are replaced wholesale so
 * a withdrawn SSVC block disappears instead of lingering as stale data.
 */
export function importSsvcFromCheckout(
  db: CveDatabase,
  options: SsvcImportOptions,
): SsvcImportResult {
  const now = options.now ?? new Date().toISOString();
  const files = listSsvcFiles(options.checkoutDir, options.wanted);
  const rows: Array<{ id: string; decision: SsvcDecision }> = [];
  const invalid: string[] = [];

  for (const relPath of files) {
    const id = path.basename(relPath, ".json");
    try {
      const text = readFileSync(path.join(options.checkoutDir, relPath), "utf8");
      const decision = parseSsvcRecord(JSON.parse(text) as unknown);
      if (decision !== null) rows.push({ id, decision });
    } catch {
      // One unreadable record must not abort the cycle; it is reported and
      // simply stays unknown for this run.
      invalid.push(id);
    }
  }

  db.runBoundedWrite(() => {
    db.handle.prepare("DELETE FROM ssvc_records").run();
    const insert = db.handle.prepare(
      "INSERT OR REPLACE INTO ssvc_records (cve_id, exploitation, automatable, technical_impact, ssvc_version, source_timestamp, catalog_date, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const row of rows) {
      insert.run(
        row.id,
        row.decision.exploitation,
        row.decision.automatable,
        row.decision.technicalImpact,
        row.decision.version,
        row.decision.timestamp,
        now,
        now,
      );
    }
    db.handle
      .prepare(
        "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run("ssvc", now, now, "succeeded", options.revision ?? now, null, null);
  });

  return {
    ok: true,
    catalogDate: now,
    total: files.length,
    parsed: rows.length,
    absent: files.length - rows.length - invalid.length,
    invalid,
    revision: options.revision ?? null,
  };
}

/** Resolve the persistent vulnrichment checkout used across cycles. */
export function resolveSsvcCacheDir(
  dataDir: string,
  env: Record<string, string | undefined> = process.env,
): string {
  const raw = env.SSVC_REPO_DIR;
  if (raw !== undefined && raw.trim() !== "") return raw;
  return path.join(dataDir, VULNRICHMENT_CACHE_DIRNAME);
}

/**
 * Clone or update the vulnrichment checkout and return a pinned revision.
 * Same discipline as the CVE cache: shallow clone, incremental fetch, and a
 * corrupt cache is recloned only when it is not a valid git tree.
 */
export function syncSsvcCache(options: {
  cacheDir: string;
  timeoutMs?: number;
  revision?: string;
  runner?: typeof runGit;
}): { revision: string; cacheReused: boolean; cacheSizeBytes: number } {
  const runner = options.runner ?? runGit;
  const revision = options.revision ?? VULNRICHMENT_REVISION;
  const timeoutMs = options.timeoutMs ?? VULNRICHMENT_DEFAULT_TIMEOUT_MS;
  const { cacheDir } = options;

  let cacheReused = false;
  if (isValidGitRepo(cacheDir, runner, timeoutMs)) {
    try {
      runner(buildFetchArgs(revision, 1), cacheDir, timeoutMs);
      cacheReused = true;
    } catch {
      // A shallow boundary can block the delta; one deepen retry reuses the
      // cache instead of paying for a re-clone.
      runner(["fetch", "--deepen", "1", "origin", revision], cacheDir, timeoutMs);
      cacheReused = true;
    }
  } else {
    if (existsSync(cacheDir)) rmSync(cacheDir, { recursive: true, force: true });
    runner(buildCloneArgs(VULNRICHMENT_REPO_URL, cacheDir, 1), path.dirname(cacheDir), timeoutMs);
  }
  // Resolve first, then detach onto the commit: `git checkout --detach <ref>`
  // rejects a ref that git parses as a path, so the SHA form is unambiguous.
  const sha = runner(["rev-parse", "FETCH_HEAD"], cacheDir, timeoutMs).trim();
  runner(["checkout", "--force", "--quiet", sha], cacheDir, timeoutMs);
  return { revision: sha, cacheReused, cacheSizeBytes: getCacheSizeBytes(cacheDir) };
}
