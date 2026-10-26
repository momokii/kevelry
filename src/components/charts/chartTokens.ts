export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "legacy",
  "unknown",
] as const;

export type SeverityKey = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_META: Record<
  SeverityKey,
  { label: string; short: string; color: string; range: string; note: string }
> = {
  critical: {
    label: "Critical",
    short: "Crit",
    color: "var(--ui-critical)",
    range: "9.0–10.0",
    note: "primary CNA CVSS v3/v4",
  },
  high: {
    label: "High",
    short: "High",
    color: "var(--ui-high)",
    range: "7.0–8.9",
    note: "primary CNA CVSS v3/v4",
  },
  medium: {
    label: "Medium",
    short: "Med",
    color: "var(--ui-medium)",
    range: "4.0–6.9",
    note: "primary CNA CVSS v3/v4",
  },
  low: {
    label: "Low",
    short: "Low",
    color: "var(--ui-low)",
    range: "0.1–3.9",
    note: "primary CNA CVSS v3/v4",
  },
  none: {
    label: "None",
    short: "None",
    color: "var(--ui-unknown)",
    range: "0.0",
    note: "scored zero, not missing",
  },
  legacy: {
    label: "Legacy",
    short: "Legacy",
    color: "var(--ui-legacy)",
    range: "v2 only",
    note: "not compared with v3/v4",
  },
  unknown: {
    label: "Unscored",
    short: "Unscored",
    color: "var(--ui-unknown)",
    range: "no CNA metric",
    note: "unknown severity, never low",
  },
};

export const EPSS_LOG_BINS = [
  { label: "<0.1%", short: "<.1", max: 0.001 },
  { label: "0.1–0.5%", short: ".1–.5", max: 0.005 },
  { label: "0.5–1%", short: ".5–1", max: 0.01 },
  { label: "1–2%", short: "1–2", max: 0.02 },
  { label: "2–5%", short: "2–5", max: 0.05 },
  { label: "5–10%", short: "5–10", max: 0.1 },
  { label: "10–20%", short: "10–20", max: 0.2 },
  { label: "20–50%", short: "20–50", max: 0.5 },
  { label: "50–100%", short: "50–100", max: 1 },
] as const;

export function formatInt(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatCompact(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}m`;
  if (value >= 10_000) return `${Math.round(value / 1000)}k`;
  if (value >= 1000) return `${(value / 1000).toFixed(1)}k`;
  return `${value}`;
}

export function sharePercent(count: number, total: number): string {
  if (total <= 0) return "0%";
  const value = (count / total) * 100;
  if (value > 0 && value < 0.01) return "<0.01%";
  if (value < 1) return `${value.toFixed(2)}%`;
  if (value < 10) return `${value.toFixed(1)}%`;
  return `${Math.round(value)}%`;
}

export function monthShort(month: string): string {
  const [year, value] = month.split("-");
  const index = Number(value) - 1;
  const names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  if (year === undefined || names[index] === undefined) return month;
  return `${names[index]} ${year.slice(2)}`;
}

export const MONTH_NAMES = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
] as const;

export function monthLong(month: string): string {
  const [year, value] = month.split("-");
  const index = Number(value) - 1;
  const name = MONTH_NAMES[index];
  if (year === undefined || name === undefined) return month;
  return `${name} ${year}`;
}
