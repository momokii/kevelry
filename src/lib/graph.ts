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

export interface GraphEdgeEvidence {
  /** Shared catalog CWE identifiers, sorted. */
  cwes: string[];
  /** Shared normalized vendor label, or null. */
  vendor: string | null;
  /** Shared reference hostnames, sorted. */
  domains: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
  kinds: GraphEdgeKind[];
  evidence: GraphEdgeEvidence;
}

export interface GraphCohort {
  focus: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  eligibleCohort: number;
  truncated: boolean;
}

export const GRAPH_DEFAULT_NODE_LIMIT = 120;

/** A host referenced by more than this share of the cohort is an advisory
 * aggregator (securityfocus, exploit-db, ...), not a relationship. */
export const GRAPH_GENERIC_HOST_SHARE = 0.15;

/** Host floor so tiny cohorts do not prune every shared host. */
export const GRAPH_GENERIC_HOST_MIN = 20;
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
 * Drop advisory-aggregator hosts from the domain dimension. A host that most
 * of the corpus references says nothing about relatedness: on the live cohort
 * securityfocus/exploit-db/osvdb otherwise produce ~99 of 119 links for any
 * center. Kept hosts stay exact; nothing is reweighted.
 */
function pruneGenericHosts(
  map: Map<string, Set<string>>,
  cohortSize: number,
): Map<string, Set<string>> {
  const usage = new Map<string, number>();
  for (const set of map.values()) {
    for (const host of set) usage.set(host, (usage.get(host) ?? 0) + 1);
  }
  const limit = Math.max(GRAPH_GENERIC_HOST_MIN, cohortSize * GRAPH_GENERIC_HOST_SHARE);
  const generic = new Set<string>();
  for (const [host, count] of usage) {
    if (count > limit) generic.add(host);
  }
  if (generic.size === 0) return map;
  const out = new Map<string, Set<string>>();
  for (const [id, set] of map) {
    const kept = new Set<string>();
    for (const host of set) if (!generic.has(host)) kept.add(host);
    out.set(id, kept);
  }
  return out;
}

function cweBuckets(map: Map<string, Set<string>>): Map<string, string[]> {
  const buckets = new Map<string, string[]>();
  for (const [id, set] of map) {
    for (const value of set) {
      const list = buckets.get(value);
      if (list === undefined) buckets.set(value, [id]);
      else list.push(id);
    }
  }
  return buckets;
}

function vendorBuckets(map: Map<string, string | null>): Map<string, string[]> {
  const buckets = new Map<string, string[]>();
  for (const [id, label] of map) {
    if (label === null || label === undefined) continue;
    const list = buckets.get(label);
    if (list === undefined) buckets.set(label, [id]);
    else list.push(id);
  }
  return buckets;
}

function domainBuckets(map: Map<string, Set<string>>): Map<string, string[]> {
  const buckets = new Map<string, string[]>();
  for (const [id, set] of map) {
    for (const value of set) {
      const list = buckets.get(value);
      if (list === undefined) buckets.set(value, [id]);
      else list.push(id);
    }
  }
  return buckets;
}

/** Highest full-cohort degree; ties fall back to EPSS then ASCII ID. */
function topHub(
  ids: readonly string[],
  degreeAll: Map<string, number>,
  epssById: Map<string, string>,
): string | null {
  const ranked = [...ids].sort((a, b) => {
    const da = degreeAll.get(a) ?? 0;
    const db = degreeAll.get(b) ?? 0;
    if (da !== db) return db - da;
    const ea = epssById.get(a) ?? null;
    const eb = epssById.get(b) ?? null;
    if (ea === null && eb === null) return a < b ? -1 : 1;
    if (ea === null) return 1;
    if (eb === null) return -1;
    const cmp = compareDecimalStrings(eb, ea) ?? 0;
    return cmp !== 0 ? cmp : a < b ? -1 : 1;
  });
  return ranked[0] ?? null;
}

function neighborsOf(
  id: string,
  cwes: Map<string, Set<string>>,
  vendors: Map<string, string | null>,
  domains: Map<string, Set<string>>,
): string[] {
  const out = new Set<string>();
  for (const [other, set] of cwes) {
    if (other !== id && intersects(cwes.get(id), set)) out.add(other);
  }
  const vendor = vendors.get(id);
  if (vendor !== null && vendor !== undefined) {
    for (const [other, label] of vendors) {
      if (other !== id && label === vendor) out.add(other);
    }
  }
  for (const [other, set] of domains) {
    if (other !== id && intersects(domains.get(id), set)) out.add(other);
  }
  return [...out];
}

function evidenceBetween(
  a: string,
  b: string,
  cwes: Map<string, Set<string>>,
  vendors: Map<string, string | null>,
  domains: Map<string, Set<string>>,
): GraphEdgeEvidence {
  const sharedCwes: string[] = [];
  const setA = cwes.get(a);
  const setB = cwes.get(b);
  if (setA !== undefined && setB !== undefined) {
    for (const value of setA) if (setB.has(value)) sharedCwes.push(value);
  }
  const vendorA = vendors.get(a) ?? null;
  const vendorB = vendors.get(b) ?? null;
  const sharedDomains: string[] = [];
  const domA = domains.get(a);
  const domB = domains.get(b);
  if (domA !== undefined && domB !== undefined) {
    for (const value of domA) if (domB.has(value)) sharedDomains.push(value);
  }
  return {
    cwes: sharedCwes.sort(),
    vendor: vendorA !== null && vendorA === vendorB ? vendorA : null,
    domains: sharedDomains.sort(),
  };
}

/**
 * Build the bounded relationship graph, always ego-centered: an explicit
 * `focus` selects its neighborhood, otherwise the center is the highest-EPSS
 * KEV record. A centerless hairball reads as noise, so there is no uncentered
 * mode. Throws RangeError on a focus outside the KEV-listed PUBLISHED cohort
 * so routes map it to 404.
 */
export function buildKevGraph(
  db: CveDatabase,
  options: { focus?: string | null; nodeLimit?: number } = {},
): GraphCohort {
  const nodeLimit = options.nodeLimit ?? GRAPH_DEFAULT_NODE_LIMIT;

  const cohort = db.handle
    .prepare(
      "SELECT r.cve_id AS id, r.title AS title, k.due_date AS dueDate " +
        "FROM kev_entries k JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = 'PUBLISHED' " +
        "ORDER BY k.cve_id ASC",
    )
    .all() as CohortRow[];
  const member = new Set(cohort.map((row) => row.id));
  if (options.focus !== undefined && options.focus !== null && !member.has(options.focus)) {
    throw new RangeError(`Focus ${options.focus} is not a KEV-listed PUBLISHED record.`);
  }

  const ids = cohort.map((row) => row.id);
  const byId = new Map(cohort.map((row) => [row.id, row]));
  const cwes = cweMap(db, ids);
  const vendors = vendorMap(db, ids);
  const domains = pruneGenericHosts(domainMap(db, ids), ids.length);
  const bands = bandMap(db, ids);
  const epssById = epssMap(db, ids);

  // Full-cohort degree per record, computed from attribute membership counts
  // (sum of groupSize-1 per shared attribute) instead of O(n^2) pairing. This
  // ranks hubs honestly across all KEV records, not just a rendered subset.
  const degreeAll = new Map<string, number>();
  const bump = (id: string, by: number): void => {
    if (by <= 0) return;
    degreeAll.set(id, (degreeAll.get(id) ?? 0) + by);
  };
  for (const bucket of [cweBuckets(cwes), vendorBuckets(vendors), domainBuckets(domains)]) {
    for (const members of bucket.values()) {
      const by = members.length - 1;
      for (const id of members) bump(id, by);
    }
  }

  const focus = options.focus ?? topHub(ids, degreeAll, epssById);
  let kept: string[];
  let truncated = false;
  if (focus !== null) {
    const neighbors = neighborsOf(focus, cwes, vendors, domains);
    // Strongest links first: more shared attributes, then higher degree.
    neighbors.sort((a, b) => {
      const ea = evidenceBetween(a, focus, cwes, vendors, domains);
      const eb = evidenceBetween(b, focus, cwes, vendors, domains);
      const sa = ea.cwes.length + ea.domains.length + (ea.vendor === null ? 0 : 1);
      const sb = eb.cwes.length + eb.domains.length + (eb.vendor === null ? 0 : 1);
      if (sa !== sb) return sb - sa;
      const da = degreeAll.get(b) ?? 0;
      const db2 = degreeAll.get(a) ?? 0;
      if (da !== db2) return da - db2;
      return a < b ? -1 : 1;
    });
    kept = [focus, ...neighbors].slice(0, nodeLimit);
    truncated = neighbors.length + 1 > nodeLimit;
  } else {
    kept = [];
  }

  const edges: GraphEdge[] = [];
  if (focus !== null) {
    // Ego star with explicit evidence per link, so "what links them" is
    // answerable without guessing from line style.
    for (const other of kept) {
      if (other === focus) continue;
      const evidence = evidenceBetween(focus, other, cwes, vendors, domains);
      const kinds: GraphEdgeKind[] = [];
      if (evidence.cwes.length > 0) kinds.push("cwe");
      if (evidence.vendor !== null) kinds.push("vendor");
      if (evidence.domains.length > 0) kinds.push("domain");
      if (kinds.length === 0) continue;
      edges.push({ from: focus, to: other, kinds, evidence });
      if (edges.length >= GRAPH_MAX_EDGES) break;
    }
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
