// Time-to-exploitation analytics: publication date → KEV confirmation date.
//
// Every number here comes from two retained columns we already store:
// `cve_records.date_published` and `kev_entries.date_added`. No estimate, no
// interpolation, no external feed. Records missing either date are excluded
// and counted; a KEV listing dated on or before the publication date is its
// own bucket rather than being clamped to zero (that happens when CISA lists a
// vulnerability before the CVE record is published).

import type { CveDatabase } from "./db";

export type LagBucket = "pre-publication" | "0-30d" | "31-90d" | "91-365d" | "1-5y" | "gt-5y";

export const LAG_BUCKETS: readonly LagBucket[] = [
  "pre-publication",
  "0-30d",
  "31-90d",
  "91-365d",
  "1-5y",
  "gt-5y",
];

export const LAG_LABELS: Record<LagBucket, string> = {
  "pre-publication": "Listed on/before publication",
  "0-30d": "Within 30 days",
  "31-90d": "31–90 days",
  "91-365d": "91–365 days",
  "1-5y": "1–5 years",
  "gt-5y": "Over 5 years",
};

const DAY_MS = 86_400_000;

/** Full-day difference between two YYYY-MM-DD or ISO timestamps. */
export function lagDays(published: string, confirmed: string): number | null {
  const publishedMs = Date.parse(
    published.length === 10 ? `${published}T00:00:00.000Z` : published,
  );
  const confirmedMs = Date.parse(
    confirmed.length === 10 ? `${confirmed}T00:00:00.000Z` : confirmed,
  );
  if (!Number.isFinite(publishedMs) || !Number.isFinite(confirmedMs)) return null;
  return Math.floor((confirmedMs - publishedMs) / DAY_MS);
}

export function bucketForLag(days: number): LagBucket {
  if (days <= 0) return "pre-publication";
  if (days <= 30) return "0-30d";
  if (days <= 90) return "31-90d";
  if (days <= 365) return "91-365d";
  if (days <= 1825) return "1-5y";
  return "gt-5y";
}

/** Publication-year cohort key; older years collapse into one node. */
export function cohortForYear(year: number, oldestYear: number): string {
  return year <= oldestYear ? `${oldestYear} or earlier` : String(year);
}

export interface SankeyLink {
  from: string;
  to: string;
  count: number;
}

export interface SankeyNode {
  id: string;
  label: string;
  column: "cohort" | "lag";
  total: number;
}

export interface TimeToKev {
  /** KEV-listed published records with both dates usable. */
  eligible: number;
  /** KEV-listed published records excluded for a missing/unparseable date. */
  excluded: number;
  nodes: SankeyNode[];
  links: SankeyLink[];
  /**
   * Median days from publication to confirmation, over records confirmed
   * *after* publication. Null when no record qualifies (a "listed before
   * publication" record is reported in its own bucket, never clamped to zero).
   */
  medianDays: number | null;
  /** Share of eligible records confirmed within 30 days. */
  within30Share: string;
  within30: number;
  fastest: Array<{ cveId: string; publishedAt: string; dateAdded: string; days: number }>;
}

interface Row {
  cve_id: string;
  date_published: string | null;
  date_added: string | null;
}

/**
 * Build the time-to-exploitation flow over KEV-listed published records.
 * `oldestYear` collapses older publication years into one cohort so the chart
 * stays readable; the collapse is stated in the label, never silent.
 */
export function buildTimeToKev(db: CveDatabase, oldestYear = 2021): TimeToKev {
  const rows = db.handle
    .prepare(
      "SELECT k.cve_id AS cve_id, r.date_published AS date_published, k.date_added AS date_added " +
        "FROM kev_entries k JOIN cve_records r ON r.cve_id = k.cve_id AND r.state = 'PUBLISHED'",
    )
    .all() as Row[];

  const parsed: Array<{
    cveId: string;
    year: number;
    days: number;
    published: string;
    added: string;
  }> = [];
  let excluded = 0;
  for (const row of rows) {
    if (row.date_published === null || row.date_added === null) {
      excluded += 1;
      continue;
    }
    const days = lagDays(row.date_published, row.date_added);
    const year = Number(row.date_published.slice(0, 4));
    if (days === null || !Number.isInteger(year)) {
      excluded += 1;
      continue;
    }
    parsed.push({
      cveId: row.cve_id,
      year,
      days,
      published: row.date_published,
      added: row.date_added,
    });
  }

  const cohortKeys = new Map<string, number>();
  for (const entry of parsed) {
    const key = cohortForYear(entry.year, oldestYear);
    cohortKeys.set(key, (cohortKeys.get(key) ?? 0) + 1);
  }
  // Newest cohort first, the collapsed one last.
  const cohortLabels = [...cohortKeys.keys()].sort((a, b) => {
    const na = Number.parseInt(a, 10);
    const nb = Number.parseInt(b, 10);
    if (Number.isNaN(na) || Number.isNaN(nb)) return a < b ? 1 : -1;
    return nb - na;
  });

  const lagCounts = new Map<LagBucket, number>();
  const flows = new Map<string, number>();
  for (const entry of parsed) {
    const bucket = bucketForLag(entry.days);
    lagCounts.set(bucket, (lagCounts.get(bucket) ?? 0) + 1);
    const cohort = cohortForYear(entry.year, oldestYear);
    const key = `${cohort}\u0000${bucket}`;
    flows.set(key, (flows.get(key) ?? 0) + 1);
  }

  const nodes: SankeyNode[] = [
    ...cohortLabels.map((label) => ({
      id: `cohort:${label}`,
      label,
      column: "cohort" as const,
      total: cohortKeys.get(label) ?? 0,
    })),
    ...LAG_BUCKETS.filter((bucket) => (lagCounts.get(bucket) ?? 0) > 0).map((bucket) => ({
      id: `lag:${bucket}`,
      label: LAG_LABELS[bucket],
      column: "lag" as const,
      total: lagCounts.get(bucket) ?? 0,
    })),
  ];
  const links: SankeyLink[] = [];
  for (const cohort of cohortLabels) {
    for (const bucket of LAG_BUCKETS) {
      const count = flows.get(`${cohort}\u0000${bucket}`) ?? 0;
      if (count > 0) links.push({ from: `cohort:${cohort}`, to: `lag:${bucket}`, count });
    }
  }

  // Median over records confirmed *after* publication: a "listed before
  // publication" record is reported in its own bucket, never clamped to zero.
  const positiveDays = parsed
    .map((entry) => entry.days)
    .filter((days) => days > 0)
    .sort((a, b) => a - b);
  const medianDays =
    positiveDays.length === 0
      ? null
      : (positiveDays[Math.floor((positiveDays.length - 1) / 2)] ?? null);
  const within30 = parsed.filter((entry) => entry.days > 0 && entry.days <= 30).length;
  const eligible = parsed.length;
  const within30Share =
    eligible === 0 ? "0%" : `${((within30 / eligible) * 100).toFixed(within30 === 0 ? 0 : 1)}%`;

  const fastest = [...parsed]
    .filter((entry) => entry.days > 0)
    .sort((a, b) => a.days - b.days || (a.cveId < b.cveId ? -1 : 1))
    .slice(0, 5)
    .map((entry) => ({
      cveId: entry.cveId,
      publishedAt: entry.published,
      dateAdded: entry.added,
      days: entry.days,
    }));

  return {
    eligible,
    excluded,
    nodes,
    links,
    medianDays,
    within30Share,
    within30,
    fastest,
  };
}
