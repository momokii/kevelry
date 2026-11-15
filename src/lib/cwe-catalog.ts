// Read path for the local, versioned CWE taxonomy catalog.
//
// The catalog is reference data, not a live feed: an importer (a later step in
// the v3 CWE work) owns every write to `cwe_catalog_meta` / `cwe_entries`, and
// this module only reads them. No network access, no upstream call, no cache.
//
// Contract:
// - `getCweCatalogMeta` reports provenance and a single status token. `empty`
//   means no accepted catalog has ever been published (the meta row is absent);
//   `ready` is the only status whose entries may be served; `stale` and
//   `unavailable` are recorded failures and resolve like an absent catalog.
// - `resolveCweIds` never throws on caller input. Ids are normalized, deduped,
//   looked up in bounded `IN` batches, and every requested id comes back with
//   one of three states: `known`, `unmapped`, or `taxonomy-unavailable`.
// - An id that cannot be normalized never disappears or becomes a blank
//   object: it resolves as `unmapped` under its raw input string, so the UI can
//   show the id and explain that it could not be mapped.
//
// The canonical URL is derived from the id, not stored, so it cannot drift from
// the key it describes. Invalid shapes have no canonical URL and carry "".

import { chunk, type CveDatabase } from "./db";

export type CweCatalogStatus = "ready" | "stale" | "unavailable" | "empty";

export type CweResolutionStatus = "known" | "unmapped" | "taxonomy-unavailable";

export interface CweRef {
  /** Normalized `CWE-<n>`; the raw input string when the id is not a valid shape. */
  id: string;
  status: CweResolutionStatus;
  name?: string;
  abstraction?: string;
  summary?: string;
  mitigation?: string;
  /** Canonical MITRE page; "" only when the input is not a valid CWE id shape. */
  url: string;
}

export interface CweCatalogMeta {
  status: CweCatalogStatus;
  version: string | null;
  sourceHash: string | null;
  retrievedAt: string | null;
  source: string;
}

/** Upstream identity used when no meta row exists yet and as the row fallback. */
export const CWE_CATALOG_SOURCE = "MITRE CWE";

/** Same bound as the repo's other id-batched lookups (see `chunk` in ./db). */
export const CWE_RESOLUTION_CHUNK = 500;

const CWE_ID_RE = /^(?:CWE-)?0*(\d{1,6})$/i;
const CANONICAL_CWE_ID_RE = /^CWE-([1-9]\d*)$/;

/**
 * MITRE's published CSV wraps remediation phases in `::PHASE:<name>::` and uses
 * the same `::…::` shape for other control markers. Opened by `::`, closed by
 * the next `::`; the inner text may itself contain single colons (e.g.
 * `::PHASE:Architecture and Design::`), so only a doubled colon terminates it.
 */
const CWE_MARKER_RE = /::(?:(?!::)[\s\S])*?::/g;

/**
 * Remove MITRE's `::…::` control markers from published taxonomy text, collapse
 * runs of whitespace to one space, and trim. Pure and total: never throws, and
 * marker-only text becomes the empty string. Applied at projection time only;
 * stored rows keep MITRE's verbatim wording.
 */
export function stripCweMarkers(text: string): string {
  if (typeof text !== "string") return "";
  return text.replace(CWE_MARKER_RE, " ").replace(/\s+/g, " ").trim();
}

/**
 * `CWE-79`, `cwe-79`, `79`, and zero-padded forms normalize to `CWE-79`.
 * Anything else — including an empty string, `CWE-0`, or a number-shaped
 * string that is too long — returns null and is never thrown on.
 */
export function normalizeCweId(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const match = CWE_ID_RE.exec(raw.trim());
  if (match === null) return null;
  const numeric = Number.parseInt(match[1] ?? "", 10);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) return null;
  return `CWE-${numeric}`;
}

/** Canonical MITRE definition page for a normalized id; "" for an invalid id. */
export function cweUrl(id: string): string {
  const match = CANONICAL_CWE_ID_RE.exec(id);
  return match === null ? "" : `https://cwe.mitre.org/data/definitions/${match[1]}.html`;
}

/**
 * The key `resolveCweIds` uses for one input: its normalized id, or the trimmed
 * raw string when the id has no valid shape. Shared with the ordered helpers
 * below so both surfaces can never disagree about which id a ref describes.
 */
function resolutionKey(raw: unknown): string {
  return normalizeCweId(raw) ?? (typeof raw === "string" ? raw.trim() : String(raw));
}

function readStatus(raw: unknown): CweCatalogStatus {
  if (raw === "ready" || raw === "stale" || raw === "unavailable") return raw;
  return raw === null || raw === undefined ? "empty" : "unavailable";
}

/**
 * Provenance and status of the accepted catalog. A missing meta row is
 * `empty`; an unreadable catalog or an unknown status token is `unavailable`.
 * Never throws: a closed or malformed database degrades to `unavailable`.
 */
export function getCweCatalogMeta(db: CveDatabase): CweCatalogMeta {
  const fallback: CweCatalogMeta = {
    status: "unavailable",
    version: null,
    sourceHash: null,
    retrievedAt: null,
    source: CWE_CATALOG_SOURCE,
  };
  try {
    const row = db.handle
      .prepare(
        "SELECT status, version, source, source_hash, retrieved_at FROM cwe_catalog_meta WHERE id = 1",
      )
      .get() as
      | {
          status: string | null;
          version: string | null;
          source: string | null;
          source_hash: string | null;
          retrieved_at: string | null;
        }
      | undefined;
    if (row === undefined) {
      return {
        status: "empty",
        version: null,
        sourceHash: null,
        retrievedAt: null,
        source: CWE_CATALOG_SOURCE,
      };
    }
    return {
      status: readStatus(row.status),
      version: row.version ?? null,
      sourceHash: row.source_hash ?? null,
      retrievedAt: row.retrieved_at ?? null,
      source: row.source ?? CWE_CATALOG_SOURCE,
    };
  } catch {
    return fallback;
  }
}

interface CweEntryRow {
  cwe_id: string;
  name: string;
  abstraction: string | null;
  summary: string | null;
  mitigation: string | null;
}

/** The catalog provenance block the API envelopes carry next to resolved refs.
 * Additive: it states which catalog (and version) labelled this payload, so a
 * client can attribute mitigation text without hard-coding a version. */
export interface CweCatalogEnvelope {
  status: CweCatalogStatus;
  version: string | null;
  retrievedAt: string | null;
  source: string;
}

/** Project the meta row for a payload envelope. Never throws: an absent or
 * unreadable catalog reports `empty`/`unavailable` with null version/date. */
export function cweCatalogEnvelope(db: CveDatabase): CweCatalogEnvelope {
  const meta = getCweCatalogMeta(db);
  return {
    status: meta.status,
    version: meta.version,
    retrievedAt: meta.retrievedAt,
    source: meta.source,
  };
}

/**
 * Resolve caller-supplied CWE ids against the accepted catalog.
 *
 * The result is keyed by normalized id (or by the trimmed raw input when the
 * id has no valid shape), so both re-ordered and differently-spelled inputs
 * collapse to one entry per id. Only `known` carries a name; an id in a valid
 * shape that is absent from the catalog is `unmapped` (still linked to its
 * canonical page), and all ids are `taxonomy-unavailable` when the catalog is
 * not `ready`.
 */
export function resolveCweIds(db: CveDatabase, ids: readonly string[]): Map<string, CweRef> {
  const out = new Map<string, CweRef>();
  const requested = new Set<string>();

  for (const raw of ids as readonly unknown[]) {
    const normalized = normalizeCweId(raw);
    if (normalized === null) {
      const key = resolutionKey(raw);
      if (!out.has(key)) {
        out.set(key, { id: key, status: "unmapped", url: "" });
      }
      continue;
    }
    requested.add(normalized);
  }

  for (const id of requested) {
    out.set(id, { id, status: "taxonomy-unavailable", url: cweUrl(id) });
  }

  if (requested.size === 0) return out;
  if (getCweCatalogMeta(db).status !== "ready") return out;

  const entries = new Map<string, CweEntryRow>();
  try {
    for (const group of chunk([...requested], CWE_RESOLUTION_CHUNK)) {
      const placeholders = group.map(() => "?").join(", ");
      const rows = db.handle
        .prepare(
          `SELECT cwe_id, name, abstraction, summary, mitigation FROM cwe_entries WHERE cwe_id IN (${placeholders})`,
        )
        .all(...group) as CweEntryRow[];
      for (const row of rows) entries.set(row.cwe_id, row);
    }
  } catch {
    // The catalog vanished between the meta read and this lookup: every id
    // keeps the taxonomy-unavailable ref seeded above, never a partial answer.
    return out;
  }

  for (const id of requested) {
    const row = entries.get(id);
    if (row === undefined) {
      out.set(id, { id, status: "unmapped", url: cweUrl(id) });
      continue;
    }
    const ref: CweRef = { id, status: "known", name: row.name, url: cweUrl(id) };
    // Long free text leaves this module stripped: MITRE markers are publishing
    // markup, not content, so no API caller ever receives `::…::`. Absent (or
    // marker-only) optional fields stay absent instead of becoming "" or null,
    // so a caller can distinguish "no mitigation text" from empty text.
    if (row.abstraction !== null) ref.abstraction = row.abstraction;
    const summary = row.summary === null ? null : stripCweMarkers(row.summary);
    if (summary !== null && summary !== "") ref.summary = summary;
    const mitigation = row.mitigation === null ? null : stripCweMarkers(row.mitigation);
    if (mitigation !== null && mitigation !== "") ref.mitigation = mitigation;
    out.set(id, ref);
  }
  return out;
}

/**
 * Turn a batched resolution back into an ordered list: caller order, one entry
 * per id, duplicates removed after normalization. Every requested id yields a
 * ref — the resolution map already carries one for every key — so an id is
 * never omitted and never becomes a blank object.
 */
export function cweRefsFromResolution(
  ids: readonly string[],
  resolved: ReadonlyMap<string, CweRef>,
): CweRef[] {
  const out: CweRef[] = [];
  const seen = new Set<string>();
  for (const raw of ids as readonly unknown[]) {
    const key = resolutionKey(raw);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(resolved.get(key) ?? { id: key, status: "unmapped", url: cweUrl(key) });
  }
  return out;
}

/**
 * Resolve one id list into ordered refs. The single-record detail path. Same
 * taxonomy-unavailable contract as `resolveCweIds`: an absent or non-ready
 * catalog still returns every id, with its canonical URL and no invented name.
 */
export function resolveCweRefs(db: CveDatabase, ids: readonly string[]): CweRef[] {
  return cweRefsFromResolution(ids, resolveCweIds(db, ids));
}

/**
 * Resolve several id lists (one rendered page) in ONE batched catalog lookup
 * while keeping each list's own order and dedupe. The priority routes use this
 * so a page of rows costs one meta read plus bounded `IN` queries, never one
 * lookup per row.
 */
export function resolveCweRefsMany(
  db: CveDatabase,
  idLists: readonly (readonly string[])[],
): CweRef[][] {
  const resolved = resolveCweIds(
    db,
    idLists.flatMap((ids) => [...ids]),
  );
  return idLists.map((ids) => cweRefsFromResolution(ids, resolved));
}
