import type { EpssFilter, KevFilter, SeverityBand } from "@/lib/search";

export type ExploreSeverity = SeverityBand;
export type ExploreKev = KevFilter;
export type ExploreEpss = EpssFilter;

export const SEVERITY_ORDER: readonly SeverityBand[] = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "legacy",
  "unknown",
];

/**
 * Severity band labels with the CVSS version they describe. Bands come from
 * the search service contract (primary-CNA metric; legacy is v2.0 only,
 * unknown is unscored under this view's policy). Labels wrap by design;
 * they are never truncated to fit a row.
 */
export const SEVERITY_LABELS: Record<SeverityBand, string> = {
  critical: "Critical · 9.0–10.0",
  high: "High · 7.0–8.9",
  medium: "Medium · 4.0–6.9",
  low: "Low · 0.1–3.9",
  none: "None · scored 0.0",
  legacy: "Legacy · v2 only",
  unknown: "Unscored · no CNA metric",
};

const SEVERITY_SET: ReadonlySet<string> = new Set(SEVERITY_ORDER);

export function isSeverityBand(value: string): value is SeverityBand {
  return SEVERITY_SET.has(value);
}

export interface ExploreInitial {
  q: string;
  dateStart: string;
  dateEnd: string;
  severity: readonly SeverityBand[];
  kev: KevFilter;
  epss: EpssFilter;
  /** Vendor/product substring over KEV catalog labels; "" means unfiltered. */
  vendor: string;
  limit: number;
}

export const EXPLORE_DEFAULT_LIMIT = 20;
export const EXPLORE_LIMIT_OPTIONS: readonly number[] = [10, 20, 50];

/** Human-readable severity line for one result row. Never invents a score. */
export function severitySignal(
  band: SeverityBand,
  baseScore: string | null,
  version: string | null,
): string {
  if (band === "unknown" || baseScore === null || version === null) {
    return "Unscored under this view's policy";
  }
  if (band === "legacy") {
    return `Legacy severity only: CVSS ${baseScore} v2.0, not compared with v3/v4`;
  }
  return `Severity ${band}: primary CNA CVSS ${baseScore} v${version} (worst CNA-provided scenario)`;
}
