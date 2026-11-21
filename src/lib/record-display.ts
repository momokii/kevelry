// Display read model for one CVE record: the shape a renderer consumes, plus
// the pure helpers that derive it from stored values.
//
// This lives in `src/lib/` on purpose. It used to sit in
// `app/api/v1/_lib/records.ts`, so a library module had to import a type from
// route code — route code depending on the library is fine, the reverse is not.
// The database walk (`loadFullRecords`) and the JSON serializers (`toCveItem`,
// `detailExtras`, `coverageFor`) stay in the route module; only the shape and
// the display derivations are here.
//
// Contract:
// - Nothing here reads a database, a clock or the network.
// - `unknown` (the catalog's own value) and `unstated` (nothing stored) stay
//   distinct; neither is ever negated into an absence claim.

import { exploitReferenceUrls } from "./exploit-ref";
import type { CvssSecondary } from "./cvss-projection";
import type { PrimaryCvss } from "./ranking";

/**
 * References the record itself tags as exploit material.
 *
 * Source: the CVE record's own `references[].tags` (CNA or ADP). A tag is the
 * publisher's classification, not proof that a working exploit exists, so the
 * UI always says "tagged", never "verified". Only http(s) URLs are kept.
 */
export type ExploitReference = { url: string };

/**
 * Catalog-stated ransomware use, as the catalog itself words it.
 *
 * `known`   - the catalog says Known.
 * `unknown` - the catalog says Unknown (its own value, not our inference).
 * `unstated` - the catalog states nothing (stored NULL).
 *
 * `unknown` and `unstated` are distinct states and are never collapsed:
 * neither is ever negated into a claim that ransomware use is absent.
 */
export type KevRansomwareUse = "known" | "unknown" | "unstated";

/**
 * The one mapping from the stored `kev_entries.ransomware_known` integer:
 * `1` -> "known", `0` -> "unknown", `NULL` -> "unstated".
 *
 * Any other non-null integer keeps the legacy reading (non-zero is Known), so
 * the old boolean alias below cannot drift from this switch.
 */
export function kevRansomwareUseOf(value: number | null | undefined): KevRansomwareUse {
  if (value === null || value === undefined) return "unstated";
  return value === 0 ? "unknown" : "known";
}

/**
 * Legacy `ransomwareKnown` boolean alias, derived from the tri-state above:
 * known -> true, unknown -> false, unstated -> null. Kept for back-compat with
 * consumers that predate `ransomwareUse`.
 */
export function legacyRansomwareKnown(use: KevRansomwareUse): boolean | null {
  if (use === "known") return true;
  if (use === "unknown") return false;
  return null;
}

/**
 * Tagged exploit references for a stored raw CVE payload, capped.
 * Unparseable payloads carry no tagged references, never a throw.
 */
export function exploitReferencesOf(rawJson: string | null, cap = 5): ExploitReference[] {
  if (rawJson === null || rawJson === "") return [];
  try {
    // Same walker as the stored flag: CNA object plus the ADP array, so a record
    // that is tagged only in an ADP container still links to its references.
    return exploitReferenceUrls(JSON.parse(rawJson) as unknown, cap).map((url) => ({ url }));
  } catch {
    return [];
  }
}

/** One CVE as every renderer reads it: stored facts plus their display shape. */
export interface FullRecord {
  cveId: string;
  state: string;
  publishedAt: string | null;
  dateUpdated: string | null;
  title: string | null;
  description: string;
  descriptionLang: string | null;
  rawJson: string | null;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRequiredAction: string | null;
  kevVulnerabilityName: string | null;
  /** Catalog-stated ransomware use; the single source for the KEV block. */
  kevRansomwareUse: KevRansomwareUse;
  /** Legacy alias derived from `kevRansomwareUse`, never a second mapping. */
  kevRansomwareKnown: boolean | null;
  kevCwes: string[];
  /** References the record tags as exploit material (never "verified PoC"). */
  exploitReferences: ExploitReference[];
  /** CISA SSVC decision points, or null when the source publishes none. */
  ssvc: {
    exploitation: string;
    automatable: string;
    technicalImpact: string;
    version: string | null;
    timestamp: string | null;
  } | null;
  epssText: string | null;
  epssPercentile: string | null;
  epssModel: string | null;
  primary: PrimaryCvss | null;
  /**
   * Every other preserved metric, bounded and labeled "context only".
   * Never a second primary: ranking/eligibility read `primary` alone.
   */
  cvssSecondary: CvssSecondary;
  /** Legacy flag kept additive; `cvssSecondary.status` supersedes it. */
  hasAdp: boolean;
}
