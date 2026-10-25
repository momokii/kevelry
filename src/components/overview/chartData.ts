import type { DayBucket } from "./loadOverview";

export const DAY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
export const MONTH_PATTERN = /^(\d{4})-(\d{2})$/;

const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

export function nextDayString(day: string): string | null {
  const match = DAY_PATTERN.exec(day);
  if (match === null) return null;
  const base = Date.parse(`${day}T00:00:00.000Z`);
  if (!Number.isFinite(base)) return null;
  const roundTrip = new Date(base).toISOString().slice(0, 10);
  if (roundTrip !== day) return null;
  return new Date(base + 86_400_000).toISOString().slice(0, 10);
}

export function trailingDaysFrom(anchorDay: string | null, count: number): string[] {
  if (anchorDay === null || nextDayString(anchorDay) === null) return [];
  if (!Number.isInteger(count) || count <= 0) return [];
  const base = Date.parse(`${anchorDay}T00:00:00.000Z`);
  const days: string[] = [];
  for (let index = count - 1; index >= 0; index -= 1) {
    days.push(new Date(base - index * 86_400_000).toISOString().slice(0, 10));
  }
  return days;
}

export function buildVolumeSeries(
  dayCounts: Record<string, number>,
  anchorDay: string | null,
  days = 30,
): DayBucket[] {
  return trailingDaysFrom(anchorDay, days).map((bucketStart) => ({
    bucketStart,
    count: dayCounts[bucketStart] ?? 0,
  }));
}

export function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function percentOf(count: number, total: number): string | null {
  if (!Number.isFinite(count) || !Number.isFinite(total) || total <= 0 || count < 0) return null;
  return `${((count / total) * 100).toFixed(count === total ? 0 : 2)}%`;
}

/**
 * Share phrase that always names its denominator, including for zero counts.
 * `noun` must describe what `total` counts (published records, scored
 * forecasts, KEV additions) so a share can never be read against the wrong
 * population.
 */
export function publishedShare(count: number, total: number, noun = "published"): string {
  const share = percentOf(count, total);
  const denominator = `${formatCount(count)} of ${formatCount(total)} ${noun}`;
  if (share === null) return denominator;
  return `${denominator} (${share})`;
}

/** Volume-chart phrasing: an empty bucket reads as an interval, not a 0%. */
export function shareText(count: number, total: number): string {
  if (count === 0) return "0 in this interval";
  return publishedShare(count, total);
}

export function dayExploreHref(day: string): string {
  const next = nextDayString(day);
  if (next === null) return "/explore";
  return `/explore?dateStart=${day}&dateEnd=${next}`;
}

export function severityExploreHref(band: string): string {
  return `/explore?severity=${encodeURIComponent(band)}`;
}

export const KEV_VIEW_HREF = "/priority?view=known-exploited";
export const FORECAST_VIEW_HREF = "/priority?view=highest-forecast";

export const EPSS_BUCKET_LABELS = [
  "0–10%",
  "10–20%",
  "20–30%",
  "30–40%",
  "40–50%",
  "50–60%",
  "60–70%",
  "70–80%",
  "80–90%",
  "90–100%",
] as const;

export function epssBucketLabel(index: number): string | null {
  if (!Number.isInteger(index) || index < 0 || index >= EPSS_BUCKET_LABELS.length) return null;
  const label: string = EPSS_BUCKET_LABELS[index] ?? "";
  return label === "" ? null : label;
}

export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "legacy",
  "unknown",
] as const;

export type SeverityBandKey = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_LABELS: Record<SeverityBandKey, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  none: "None (scored 0)",
  legacy: "Legacy (CVSS v2 only)",
  unknown: "Unscored",
};

export const SEVERITY_PRIMARY_BANDS: SeverityBandKey[] = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
];

export interface SeverityRow {
  band: SeverityBandKey;
  label: string;
  count: number;
}

export function severityRows(bands: Record<string, number>): SeverityRow[] {
  return SEVERITY_ORDER.map((band) => ({
    band,
    label: SEVERITY_LABELS[band],
    count: bands[band] ?? 0,
  }));
}

export function monthLabel(month: string): string | null {
  const match = MONTH_PATTERN.exec(month);
  if (match === null) return null;
  const monthIndex = Number(match[2]);
  if (monthIndex < 1 || monthIndex > 12) return null;
  return `${MONTH_NAMES[monthIndex - 1]} ${match[1]}`;
}
