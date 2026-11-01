import type { CveDatabase } from "./db";
import { getAcceptedEpssDate } from "./priority";
import { compareDecimalStrings, selectPrimaryCvss } from "./ranking";
import { severityBandFor } from "./search";

// Bounded KEV-cohort relationship graph (v2 research Tier: "second brain").
//
// Nodes are KEV-listed PUBLISHED CVEs; edges join records that share an
// honest, labeled attribute: a catalog CWE, a normalized vendor label, or a
// reference hostname. No text-similarity guessing, no invented relations:
// every edge kind is inspectable on both endpoints. Bounds are part of the
// contract (node/edge caps, deterministic order), never silent sampling.

export type GraphEdgeKind = "cwe" | "vendor" | "domain";

export interface GraphNode {
  id: string;
  title: string;
  band: string | null;
  epss: string | null;
  kevDueDate: string | null;
  degree: number;
}

export interface GraphEdge {
  from: string;
  to: string;
  kinds: GraphEdgeKind[];
}

export interface GraphCohort {
  focus: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  eligibleCohort: number;
  truncated: boolean;
}

export const GRAPH_DEFAULT_NODE_LIMIT = 120;
export const GRAPH_MAX_NODE_LIMIT = 300;
export const GRAPH_MAX_EDGES = 1500;

function normalizeVendor(value: string | null): string | null {
  if (value === null) return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed === "" ? null : trimmed;
}

function hostOf(url: string): string | null {
  if (!url.startsWith("https://") && !url.startsWith("http://")) return null;
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host === "" ? null : host;
  } catch {
    return null;
  }
}

function domainsOf(rawJson: string | null, cap: number): Set<string> {
  const out = new Set<string>();
  if (rawJson === null || rawJson === "") return out;
  try {
    const root = JSON.parse(rawJson) as {
      containers?: { cna?: { references?: unknown[] }; adp?: { references?: unknown[] } };
    };
    const containers = root.containers;
    if (containers === undefined || containers === null) return out;
    for (const key of ["cna", "adp"] as const) {
      const section = containers[key] as { references?: unknown } | undefined;
      const refs = section?.references;
      if (!Array.isArray(refs)) continue;
      for (const entry of refs) {
        const url = (entry as { url?: unknown }).url;
        if (typeof url !== "string") continue;
        const host = hostOf(url);
        if (host !== null) out.add(host);
        if (out.size >= cap) return out;
      }
    }
  } catch {
    // Unparseable payloads contribute no domains, never a throw.
  }
  return out;
}

interface CohortRow {
  id: string;
  title: string | null;
  dueDate: string | null;
}

/**
 * Build the bounded relationship graph. `focus` selects an ego neighborhood
 * (the focus plus every directly linked record); without it the cohort is
 * the top-EPSS KEV members up to the node limit. Throws RangeError on a
 * focus outside the KEV-listed PUBLISHED cohort so routes map it to 404.
 */
export function buildKevGraph(
  db: CveDatabase,
  options: { focus?: string | null; nodeLimit?: number } = {},
): GraphCohort {
  const nodeLimit = options.nodeLimit ?? GRAPH_DEFAULT_NODE_LIMIT;
  const focus = options.focus ?? null;

  const cohort = db.handle
    .prepare(
      "SELECT r.cve_id AS id, r.title AS title, k.due_date AS dueDate " +
        "FROM kev_entries k JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = 'PUBLISHED' " +
        "ORDER BY k.cve_id ASC",
    )
    .all() as CohortRow[];
  const member = new Set(cohort.map((row) => row.id));
  if (focus !== null && !member.has(focus)) {
    throw new RangeError(`Focus ${focus} is not a KEV-listed PUBLISHED record.`);
  }

  const ids = cohort.map((row) => row.id);
  const byId = new Map(cohort.map((row) => [row.id, row]));
  const cwes = cweMap(db, ids);
  const vendors = vendorMap(db, ids);
  const domains = domainMap(db, ids);
  const bands = bandMap(db, ids);
  const epssById = epssMap(db, ids);

  const linked = (id: string): Set<string> => {
    const out = new Set<string>();
    for (const [other, set] of cwes) {
      if (other !== id && intersects(cwes.get(id), set)) out.add(other);
    }
    for (const [other, label] of vendors) {
      if (other !== id && label !== null && label === vendors.get(id)) out.add(other);
    }
    for (const [other, set] of domains) {
      if (other !== id && intersects(domains.get(id), set)) out.add(other);
    }
    return out;
  };

  let kept: string[];
  let truncated = false;
  if (focus !== null) {
    const neighborhood = [...linked(focus)].sort();
    kept = [focus, ...neighborhood].slice(0, nodeLimit);
    truncated = neighborhood.length + 1 > nodeLimit;
  } else {
    const ranked = [...ids].sort((a, b) => {
      const ea = epssById.get(a) ?? null;
      const eb = epssById.get(b) ?? null;
      if (ea === null && eb === null) return a < b ? -1 : 1;
      if (ea === null) return 1;
      if (eb === null) return -1;
      const cmp = compareDecimalStrings(eb, ea) ?? 0;
      return cmp !== 0 ? cmp : a < b ? -1 : 1;
    });
    kept = ranked.slice(0, nodeLimit);
    truncated = ranked.length > nodeLimit;
  }
  const keptSet = new Set(kept);

  const edges: GraphEdge[] = [];
  const sorted = [...kept].sort();
  for (let i = 0; i < sorted.length; i += 1) {
    const from = sorted[i] as string;
    for (let j = i + 1; j < sorted.length; j += 1) {
      const to = sorted[j] as string;
      const kinds: GraphEdgeKind[] = [];
      if (intersects(cwes.get(from), cwes.get(to))) kinds.push("cwe");
      const vendor = vendors.get(from);
      if (vendor !== null && vendor !== undefined && vendor === vendors.get(to)) {
        kinds.push("vendor");
      }
      if (intersects(domains.get(from), domains.get(to))) kinds.push("domain");
      if (kinds.length > 0) edges.push({ from, to, kinds });
      if (edges.length >= GRAPH_MAX_EDGES) break;
    }
    if (edges.length >= GRAPH_MAX_EDGES) break;
  }

  const nodes: GraphNode[] = kept.map((id) => {
    const row = byId.get(id);
    const trimmed = typeof row?.title === "string" ? row.title.trim() : "";
    const degree = edges.filter((edge) => edge.from === id || edge.to === id).length;
    return {
      id,
      title: trimmed !== "" ? trimmed : id,
      band: bands.get(id) ?? null,
      epss: epssById.get(id) ?? null,
      kevDueDate: row?.dueDate ?? null,
      degree,
    };
  });

  return {
    focus,
    nodes,
    edges,
    eligibleCohort: cohort.length,
    truncated: truncated || edges.length >= GRAPH_MAX_EDGES,
  };
}

function intersects(a: Set<string> | undefined, b: Set<string> | undefined): boolean {
  if (a === undefined || b === undefined || a.size === 0 || b.size === 0) return false;
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const entry of small) {
    if (large.has(entry)) return true;
  }
  return false;
}

function chunked<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    out.push(items.slice(index, index + size));
  }
  return out;
}

function cweMap(db: CveDatabase, ids: readonly string[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const group of chunked(ids, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(`SELECT cve_id, cwe_id FROM kev_cwes WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; cwe_id: string }>;
    for (const row of rows) {
      const set = out.get(row.cve_id);
      if (set === undefined) out.set(row.cve_id, new Set([row.cwe_id]));
      else set.add(row.cwe_id);
    }
  }
  return out;
}

function vendorMap(db: CveDatabase, ids: readonly string[]): Map<string, string | null> {
  const out = new Map<string, string | null>();
  for (const group of chunked(ids, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(`SELECT cve_id, vendor_project FROM kev_entries WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; vendor_project: string | null }>;
    for (const row of rows) out.set(row.cve_id, normalizeVendor(row.vendor_project));
  }
  return out;
}

function domainMap(db: CveDatabase, ids: readonly string[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const group of chunked(ids, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(`SELECT cve_id, raw_json FROM cve_records WHERE cve_id IN (${placeholders})`)
      .all(...group) as Array<{ cve_id: string; raw_json: string | null }>;
    for (const row of rows) out.set(row.cve_id, domainsOf(row.raw_json, 24));
  }
  return out;
}

function bandMap(db: CveDatabase, ids: readonly string[]): Map<string, string | null> {
  const out = new Map<string, string | null>();
  for (const group of chunked(ids, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(
        `SELECT cve_id, origin, version, base_score, vector, source_order FROM cvss_metrics WHERE cve_id IN (${placeholders})`,
      )
      .all(...group) as Array<{
      cve_id: string;
      origin: string;
      version: string;
      base_score: string;
      vector: string;
      source_order: number;
    }>;
    const byId = new Map<
      string,
      Array<{
        cve_id: string;
        origin: string;
        version: string;
        base_score: string;
        vector: string;
        source_order: number;
      }>
    >();
    for (const row of rows) {
      const list = byId.get(row.cve_id);
      if (list === undefined) byId.set(row.cve_id, [row]);
      else list.push(row);
    }
    for (const [cveId, metrics] of byId) {
      const primary = selectPrimaryCvss(
        metrics.map((metric, index) => ({
          origin: metric.origin,
          version: metric.version,
          baseScore: metric.base_score,
          vector: metric.vector,
          sourceOrder: Number.isInteger(metric.source_order) ? metric.source_order : index,
        })),
      );
      out.set(cveId, primary === null ? null : severityBandFor(primary));
    }
  }
  return out;
}

function epssMap(db: CveDatabase, ids: readonly string[]): Map<string, string> {
  const out = new Map<string, { epss: string; model: string }>();
  const accepted = getAcceptedEpssDate(db);
  if (accepted === null) return new Map();
  for (const group of chunked(ids, 500)) {
    const placeholders = group.map(() => "?").join(", ");
    const rows = db.handle
      .prepare(
        `SELECT cve_id, epss, model_version FROM epss_daily WHERE score_date = ? AND cve_id IN (${placeholders})`,
      )
      .all(accepted, ...group) as Array<{ cve_id: string; epss: string; model_version: string }>;
    for (const row of rows) {
      const prior = out.get(row.cve_id);
      if (prior === undefined || row.model_version > prior.model) {
        out.set(row.cve_id, { epss: row.epss, model: row.model_version });
      }
    }
  }
  return new Map([...out].map(([id, entry]) => [id, entry.epss]));
}
