// CISA KEV catalog snapshot importer (plan todo 9).
//
// DATA_WORKFLOW.md (KEV and EPSS Ingestion): import KEV as a complete
// validated catalog snapshot. Validate declared/actual counts, unique valid
// IDs, required fields, and catalog date/version. Replace current membership
// only after validation; removal means "not in the new catalog", not "never
// exploited". Membership history lives in kev_history, separate from the
// current kev_entries flag. Unmatched IDs are reported, never manufactured
// into cve_records.
//
// Must NOT do: no partial membership updates, no first-exploit-date
// inference (dateAdded is catalog-entry date only).

import type { CveDatabase } from "./db";

export const KEV_FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export const KEV_MAX_ENTRIES = 100_000;
export const KEV_MAX_STRING = 512;

export class KevImportError extends Error {
  readonly name = "KevImportError";
}

export const KEV_MAX_CWES = 16;
const CWE_ID_PATTERN = /^CWE-\d{1,5}$/;

export interface KevValidatedEntry {
  cveId: string;
  dateAdded: string;
  vendorProject: string | null;
  product: string | null;
  /** Federal remediation deadline (calendar date) or null when absent/malformed. */
  dueDate: string | null;
  requiredAction: string | null;
  vulnerabilityName: string | null;
  /** 1 = catalog says ransomware use is Known, 0 = Unknown, null = unstated. */
  ransomwareKnown: number | null;
  cwes: string[];
}

export interface KevValidatedCatalog {
  catalogVersion: string;
  catalogDate: string;
  declaredCount: number;
  entries: KevValidatedEntry[];
}

export interface KevImportResult {
  ok: true;
  catalogVersion: string;
  catalogDate: string;
  total: number;
  added: string[];
  removed: string[];
  unmatched: string[];
}

export interface KevImportOptions {
  now?: string;
}

const CVE_ID_PATTERN = /^CVE-(19|20)\d{2}-\d{4,}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const DATE_ONLY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

function isWellFormedTimestamp(value: string): boolean {
  return TIMESTAMP_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

function isWellFormedDateOnly(value: string): boolean {
  if (!DATE_ONLY_PATTERN.test(value)) return false;
  const ms = Date.parse(`${value}T00:00:00.000Z`);
  if (!Number.isNaN(ms)) {
    return new Date(ms).toISOString().slice(0, 10) === value;
  }
  return false;
}

// dateAdded in the live catalog is a calendar date ("2021-11-03"); the
// contract fixtures use full timestamps. Accept either, store verbatim.
function isWellFormedKevDate(value: string): boolean {
  return isWellFormedTimestamp(value) || isWellFormedDateOnly(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value === "object" && value !== null) return value as Record<string, unknown>;
  return null;
}

function boundedString(value: unknown): string | null {
  if (typeof value !== "string" || value === "" || value.length > KEV_MAX_STRING) return null;
  return value;
}

function optionalBoundedString(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > KEV_MAX_STRING) return null;
  return value === "" ? null : value;
}

function fail(message: string): never {
  throw new KevImportError(message);
}

/** Validate a raw parsed KEV catalog document without touching the database. */
export function parseKevCatalog(raw: unknown): KevValidatedCatalog {
  const doc = asRecord(raw);
  if (doc === null) fail("KEV catalog must be a JSON object.");

  const catalogVersion = boundedString(doc.catalogVersion);
  if (catalogVersion === null) fail("KEV catalog is missing a valid catalogVersion.");

  const catalogDateRaw = boundedString(doc.dateReleased);
  if (catalogDateRaw === null || !isWellFormedTimestamp(catalogDateRaw)) {
    fail(`KEV catalog has a malformed dateReleased ${JSON.stringify(doc.dateReleased)}.`);
  }
  const catalogDate = catalogDateRaw as string;

  const declaredCount = doc.count;
  if (
    typeof declaredCount !== "number" ||
    !Number.isInteger(declaredCount) ||
    declaredCount < 0 ||
    declaredCount > KEV_MAX_ENTRIES
  ) {
    fail(`KEV catalog has an invalid count ${JSON.stringify(doc.count)}.`);
  }

  const vulnerabilities = doc.vulnerabilities;
  if (!Array.isArray(vulnerabilities)) fail("KEV catalog is missing its vulnerabilities array.");
  const rows = vulnerabilities as unknown[];
  if (rows.length > KEV_MAX_ENTRIES) {
    fail(`KEV catalog exceeds the ${KEV_MAX_ENTRIES}-entry safety bound.`);
  }
  if (rows.length !== (declaredCount as number)) {
    fail(
      `KEV declared count ${String(declaredCount)} does not match actual rows ${rows.length}; import aborted.`,
    );
  }

  const seen = new Set<string>();
  const entries: KevValidatedEntry[] = [];
  for (const row of rows) {
    const vuln = asRecord(row);
    if (vuln === null) fail("KEV catalog contains a non-object vulnerability entry.");
    const entry = vuln as Record<string, unknown>;
    const cveId = entry.cveID;
    if (typeof cveId !== "string" || !CVE_ID_PATTERN.test(cveId)) {
      fail(`KEV catalog contains an invalid cveID ${JSON.stringify(entry.cveID)}.`);
    }
    const dateAdded = entry.dateAdded;
    if (typeof dateAdded !== "string" || !isWellFormedKevDate(dateAdded)) {
      fail(`KEV catalog has a malformed dateAdded ${JSON.stringify(dateAdded)} for ${cveId}.`);
    }
    if (seen.has(cveId as string)) fail(`KEV catalog contains a duplicate ID "${cveId}".`);
    seen.add(cveId as string);
    // Enrichment degrades to null/empty, never to an import failure: these
    // fields inform displays, never membership.
    const dueRaw = entry.dueDate;
    const dueDate = typeof dueRaw === "string" && isWellFormedDateOnly(dueRaw) ? dueRaw : null;
    const ransomwareRaw = entry.knownRansomwareCampaignUse;
    const ransomwareKnown = ransomwareRaw === "Known" ? 1 : ransomwareRaw === "Unknown" ? 0 : null;
    const cwes: string[] = [];
    if (Array.isArray(entry.cwes)) {
      for (const candidate of entry.cwes) {
        if (typeof candidate === "string" && CWE_ID_PATTERN.test(candidate)) {
          if (!cwes.includes(candidate)) cwes.push(candidate);
          if (cwes.length >= KEV_MAX_CWES) break;
        }
      }
    }
    entries.push({
      cveId: cveId as string,
      dateAdded: dateAdded as string,
      vendorProject: optionalBoundedString(entry.vendorProject),
      product: optionalBoundedString(entry.product),
      dueDate,
      requiredAction: optionalBoundedString(entry.requiredAction),
      vulnerabilityName: optionalBoundedString(entry.vulnerabilityName),
      ransomwareKnown,
      cwes,
    });
  }

  return { catalogVersion, catalogDate, declaredCount: declaredCount as number, entries };
}

function recordSyncRun(
  db: CveDatabase,
  revision: string | null,
  status: "succeeded" | "failed",
  now: string,
  error: string | null,
): void {
  db.handle
    .prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .run("kev", now, now, status, revision, null, error);
}

function currentKevIds(db: CveDatabase): Set<string> {
  const rows = db.handle.prepare("SELECT cve_id FROM kev_entries").all() as Array<{
    cve_id: string;
  }>;
  return new Set(rows.map((row) => row.cve_id));
}

function knownCveIds(db: CveDatabase): Set<string> {
  const rows = db.handle.prepare("SELECT cve_id FROM cve_records").all() as Array<{
    cve_id: string;
  }>;
  return new Set(rows.map((row) => row.cve_id));
}

/**
 * Validate a raw KEV catalog and atomically replace kev_entries.
 * Validation failures throw KevImportError with membership untouched
 * (last-known-good intact). History rows are append-only: removals stamp
 * removed_in_catalog but never delete history.
 */
export function importKevCatalog(
  db: CveDatabase,
  raw: unknown,
  options: KevImportOptions = {},
): KevImportResult {
  const now = options.now ?? new Date().toISOString();
  let catalog: KevValidatedCatalog;
  try {
    catalog = parseKevCatalog(raw);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    db.runBoundedWrite(() => recordSyncRun(db, null, "failed", now, detail));
    throw error;
  }

  const previousIds = currentKevIds(db);
  const nextIds = new Set(catalog.entries.map((entry) => entry.cveId));
  const added = [...nextIds].filter((id) => !previousIds.has(id)).sort();
  const removed = [...previousIds].filter((id) => !nextIds.has(id)).sort();
  const unmatched = [...nextIds].filter((id) => !knownCveIds(db).has(id)).sort();

  db.runBoundedWrite(() => {
    db.handle.prepare("DELETE FROM kev_entries").run();
    db.handle.prepare("DELETE FROM kev_cwes").run();
    const insertCwe = db.handle.prepare(
      "INSERT OR IGNORE INTO kev_cwes (cve_id, cwe_id) VALUES (?, ?)",
    );
    const insertEntry = db.handle.prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, product, due_date, required_action, vulnerability_name, ransomware_known, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    for (const entry of catalog.entries) {
      insertEntry.run(
        entry.cveId,
        entry.dateAdded,
        catalog.catalogDate,
        entry.vendorProject,
        entry.product,
        entry.dueDate,
        entry.requiredAction,
        entry.vulnerabilityName,
        entry.ransomwareKnown,
        now,
      );
      for (const cwe of entry.cwes) insertCwe.run(entry.cveId, cwe);
    }
    const insertHistory = db.handle.prepare(
      "INSERT INTO kev_history (cve_id, date_added, catalog_date, removed_in_catalog, recorded_at) VALUES (?, ?, ?, ?, ?)",
    );
    const stampRemoval = db.handle.prepare(
      "UPDATE kev_history SET removed_in_catalog = ? WHERE cve_id = ? AND removed_in_catalog IS NULL",
    );
    for (const id of added) {
      const entry = catalog.entries.find((candidate) => candidate.cveId === id);
      insertHistory.run(id, entry?.dateAdded ?? "", catalog.catalogDate, null, now);
    }
    for (const id of removed) {
      stampRemoval.run(catalog.catalogVersion, id);
    }
    recordSyncRun(db, catalog.catalogVersion, "succeeded", now, null);
  });

  return {
    ok: true,
    catalogVersion: catalog.catalogVersion,
    catalogDate: catalog.catalogDate,
    total: catalog.entries.length,
    added,
    removed,
    unmatched,
  };
}

/**
 * Fetch the live KEV catalog JSON. Fixed URL only (no caller-supplied URL,
 * so server-side requests cannot be redirected at arbitrary hosts).
 */
export async function fetchKevCatalog(fetcher: typeof fetch = fetch): Promise<unknown> {
  const response = await fetcher(KEV_FEED_URL, {
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new KevImportError(`KEV fetch failed: HTTP ${response.status}.`);
  }
  const text = await response.text();
  if (text.length > 50_000_000) {
    throw new KevImportError("KEV response exceeds the 50MB safety bound; import aborted.");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new KevImportError("KEV response is not valid JSON; import aborted.");
  }
}

/** Fetch the live catalog, then validate and atomically publish it. */
export async function importKevFromUrl(
  db: CveDatabase,
  options: KevImportOptions & { fetcher?: typeof fetch } = {},
): Promise<KevImportResult> {
  const raw = await fetchKevCatalog(options.fetcher ?? fetch);
  return importKevCatalog(db, raw, { now: options.now });
}
