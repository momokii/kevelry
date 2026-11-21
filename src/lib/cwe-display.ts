// Display rules for the CWE taxonomy and the KEV ransomware-use signal.
//
// Pure formatting: no database, no React, no fetch. `cwe-catalog.ts` owns
// resolution and `record-display.ts` owns the stored tri-state; this module owns
// the wording, so a chip name, a disclosed mitigation and a ransomware label are
// each stated once and shared by every renderer and test.
//
// Contract:
// - Nothing here infers: an id the taxonomy does not know gets no name, and a
//   mitigation is disclosed only when the taxonomy published one.
// - `unknown` (the catalog's own value) and `unstated` (nothing stored) are
//   distinct labels, never collapsed and never negated into "no ransomware".

import type { KevRansomwareUse } from "./record-display";

import type { CweRef } from "./cwe-catalog";

/** Id plus state word for an id the loaded catalog does not carry. */
export const CWE_UNMAPPED_STATE = "not in the loaded catalog";

/** Said once at block level for every id; never repeated per chip. */
export const CWE_TAXONOMY_UNAVAILABLE = "taxonomy unavailable";

/** Exact catalog wording per stored tri-state. `unknown` is the catalog's own
 * Unknown value; `unstated` means the field was absent. Neither is a negation,
 * and no state ever reads as a ransomware-free claim. */
export const KEV_RANSOMWARE_USE_LABELS: Record<KevRansomwareUse, string> = {
  known: "Known (catalog)",
  unknown: "Unknown (catalog)",
  unstated: "Not stated",
};

/** Published name for a `known` chip, trimmed; null when the taxonomy
 * published none (or the id is unmapped / taxonomy-unavailable). */
export function cweChipName(cwe: CweRef): string | null {
  if (cwe.status !== "known") return null;
  if (typeof cwe.name !== "string") return null;
  const name = cwe.name.trim();
  return name === "" ? null : name;
}

/** Mitigation text that may be disclosed: only `known` ids whose taxonomy
 * published non-empty guidance. Marker stripping already happened server-side. */
export function cweMitigations(cwes: readonly CweRef[]): Array<{ id: string; mitigation: string }> {
  const out: Array<{ id: string; mitigation: string }> = [];
  for (const cwe of cwes) {
    if (cwe.status !== "known") continue;
    if (typeof cwe.mitigation !== "string") continue;
    const mitigation = cwe.mitigation.trim();
    if (mitigation === "") continue;
    out.push({ id: cwe.id, mitigation });
  }
  return out;
}
