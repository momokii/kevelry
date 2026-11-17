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
 * MITRE's published remediation grammar, read back from the catalog itself:
 *
 *   ::PHASE:<phase>[:STRATEGY:<strategy>]:DESCRIPTION:<prose>::
 *
 * `::` opens and closes each marker run, `<phase>` and `<strategy>` are free
 * text (they carry spaces and commas: `Architecture and Design Operation`,
 * `Attack Surface Reduction, Environment Hardening`), `STRATEGY` is optional,
 * and one field can carry several runs. A run with no `DESCRIPTION` carries no
 * prose at all. So a marker does NOT end at the next `::` in a way that can be
 * paired off: the prose sits between the opener and the closing `::`, and the
 * value is capped at 600 code points, which can leave the last run cut inside
 * its own marker (`::PHASE:`, `::P…`). Prose can also contain `::` itself
 * (`std::auto_ptr`). Splitting on `::` and classifying each segment keeps the
 * prose, which a pair regex deletes along with the markup it sat between.
 */
const CWE_MARKER_DELIMITER = "::";

/** The field that introduces a run's prose. Prose is everything after it. */
const CWE_DESCRIPTION_FIELD = "DESCRIPTION:";
const CWE_DESCRIPTION_PREFIX = `:${CWE_DESCRIPTION_FIELD}`;

/** A segment that opens with one of these keys is markup, never prose. */
const CWE_TAG_KEY_RE = /^(?:PHASE|STRATEGY|DESCRIPTION)(?::|$)/;

/** A `:DESCRIPTION:` field can only follow a run that a key opened. */
const CWE_MARKER_OPEN_RE = /^(?:PHASE|STRATEGY):/;

/**
 * A truncation remnant: the code-point cap landed inside a marker and left a
 * bare upper-case field name (or the start of one) with no body — `PHASE`,
 * `PHASE:`, `PHAS…`, `P…`. Only consulted for the final segment, because the
 * cap can only cut the end of the field; dropped so a stored half-marker never
 * leaks into prose.
 */
const CWE_TRUNCATED_MARKER_RE = /^[A-Z][A-Z0-9_]*:?(?:…)?$/;

/**
 * The prose one `::`-delimited segment contributes; `null` means it is markup.
 *
 * Text before the first `::` was never inside a marker, so it is prose.
 * Everything after one is prose only when the segment ends a marker run: the
 * part after `:DESCRIPTION:` (dropping the `PHASE`/`STRATEGY` fields in front
 * of it), the part after a bare `DESCRIPTION:` (an empty phase name makes
 * `::PHASE::DESCRIPTION:…`, which splits there), or any segment a marker key
 * does not open — that last case is how prose containing `::` survives.
 */
function cweSegmentProse(segment: string, isFirst: boolean, isLast: boolean): string | null {
  if (segment.trim() === "") return null;
  if (isFirst) return segment;

  const descriptionAt = segment.indexOf(CWE_DESCRIPTION_PREFIX);
  if (descriptionAt !== -1 && CWE_MARKER_OPEN_RE.test(segment)) {
    return segment.slice(descriptionAt + CWE_DESCRIPTION_PREFIX.length);
  }
  if (segment.startsWith(CWE_DESCRIPTION_FIELD)) {
    return segment.slice(CWE_DESCRIPTION_FIELD.length);
  }
  // A marker key with no `DESCRIPTION:` is a tag-only run or a run the cap cut
  // before its prose: either way it contributes nothing.
  if (CWE_TAG_KEY_RE.test(segment)) return null;
  if (isLast && CWE_TRUNCATED_MARKER_RE.test(segment)) return null;
  return segment;
}

/**
 * Recover the prose from published taxonomy text: drop MITRE's `::`-delimited
 * marker fields, keep the prose they carry, join the pieces with one space,
 * collapse whitespace, and trim. Pure and total: never throws, and marker-only
 * text becomes the empty string. Applied on the read path and, before the
 * length cap, at ingest — so neither a stored row nor a payload can carry a
 * marker, a marker's fields, or a partial marker left by truncation.
 */
export function stripCweMarkers(text: string): string {
  if (typeof text !== "string") return "";
  const segments = text.split(CWE_MARKER_DELIMITER);
  let last = segments.length - 1;
  while (last > 0 && (segments[last] ?? "").trim() === "") last -= 1;

  const pieces: string[] = [];
  for (let index = 0; index < segments.length; index += 1) {
    const prose = cweSegmentProse(segments[index] ?? "", index === 0, index === last);
    if (prose !== null) pieces.push(prose);
  }
  return pieces.join(" ").replace(/\s+/g, " ").trim();
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
