"use client";

import { useTimeZone } from "./DisplayPrefs";

const MONTHS = [
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

const DATE_ONLY_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

function pad2(value: number): string {
  return value < 10 ? `0${value}` : `${value}`;
}

export function zoneOffsetMinutes(instant: Date, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(instant);
  const get = (type: string): number => {
    const part = parts.find((entry) => entry.type === type);
    return part ? Number(part.value) : 0;
  };
  const asUtc = Date.UTC(
    get("year"),
    get("month") - 1,
    get("day"),
    get("hour"),
    get("minute"),
    get("second"),
  );
  return Math.round((asUtc - instant.getTime()) / 60000);
}

function isDaylight(instant: Date, timeZone: string): boolean {
  const january = new Date(Date.UTC(instant.getUTCFullYear(), 0, 1));
  return zoneOffsetMinutes(instant, timeZone) !== zoneOffsetMinutes(january, timeZone);
}

export function zoneAbbreviation(instant: Date, timeZone: string): string {
  switch (timeZone) {
    case "Asia/Jakarta":
      return "WIB";
    case "Asia/Singapore":
      return "SGT";
    case "UTC":
      return "UTC";
    case "Europe/London":
      return isDaylight(instant, timeZone) ? "BST" : "GMT";
    case "America/New_York":
      return isDaylight(instant, timeZone) ? "EDT" : "EST";
    case "America/Los_Angeles":
      return isDaylight(instant, timeZone) ? "PDT" : "PST";
    default:
      return timeZone;
  }
}

function partsInZone(
  instant: Date,
  timeZone: string,
): { day: string; month: string; year: string; hour: string; minute: string } {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone,
    hourCycle: "h23",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).formatToParts(instant);
  const get = (type: string): string => parts.find((entry) => entry.type === type)?.value ?? "";
  const monthIndex = Number(get("month")) - 1;
  return {
    day: get("day"),
    month: MONTHS[monthIndex] ?? get("month"),
    year: get("year"),
    hour: get("hour") === "24" ? "00" : get("hour"),
    minute: get("minute"),
  };
}

function resolveZone(timeZone: string | undefined, fallback: string): string {
  if (timeZone) {
    try {
      new Intl.DateTimeFormat("en-GB", { timeZone });
      return timeZone;
    } catch {
      return fallback;
    }
  }
  return fallback;
}

export function formatLedgerTime(
  value: string | null | undefined,
  timeZone: string,
): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed === "") {
    return null;
  }
  const dateOnly = DATE_ONLY_PATTERN.exec(trimmed);
  if (dateOnly) {
    const year = Number(dateOnly[1]);
    const month = Number(dateOnly[2]);
    const day = Number(dateOnly[3]);
    if (month < 1 || month > 12 || day < 1 || day > 31) {
      return null;
    }
    return `${pad2(day)} ${MONTHS[month - 1]} ${year}`;
  }
  const instant = new Date(trimmed);
  if (Number.isNaN(instant.getTime())) {
    return null;
  }
  let zone = timeZone;
  try {
    partsInZone(instant, zone);
  } catch {
    zone = "UTC";
  }
  const parts = partsInZone(instant, zone);
  return `${parts.day} ${parts.month} ${parts.year}, ${parts.hour}:${parts.minute} ${zoneAbbreviation(instant, zone)}`;
}

export function formatLedgerRelative(
  value: string | null | undefined,
  nowMs: number = Date.now(),
): string | null {
  if (value === null || value === undefined || value.trim() === "") {
    return null;
  }
  if (DATE_ONLY_PATTERN.test(value.trim())) {
    return null;
  }
  const instant = new Date(value.trim());
  if (Number.isNaN(instant.getTime())) {
    return null;
  }
  const diffMs = nowMs - instant.getTime();
  const absMs = Math.abs(diffMs);
  const minute = 60 * 1000;
  const hour = 60 * minute;
  const day = 24 * hour;
  const unit = (count: number, singular: string): string =>
    `${count} ${singular}${count === 1 ? "" : "s"}`;
  if (absMs < minute) {
    return "just now";
  }
  if (absMs < hour) {
    const count = Math.floor(absMs / minute);
    return diffMs >= 0 ? `${unit(count, "minute")} ago` : `in ${unit(count, "minute")}`;
  }
  if (absMs < day) {
    const count = Math.floor(absMs / hour);
    return diffMs >= 0 ? `${unit(count, "hour")} ago` : `in ${unit(count, "hour")}`;
  }
  const count = Math.floor(absMs / day);
  return diffMs >= 0 ? `${unit(count, "day")} ago` : `in ${unit(count, "day")}`;
}

type TimeTextProps = {
  value?: string | null;
  timeZone?: string;
  showRelative?: boolean;
  now?: number;
  testId?: string;
};

export function TimeText({
  value,
  timeZone: zoneProp,
  showRelative = false,
  now,
  testId,
}: TimeTextProps) {
  const ambientZone = useTimeZone();
  const zone = resolveZone(zoneProp, ambientZone);
  const formatted = formatLedgerTime(value ?? null, zone);

  if (formatted === null) {
    return (
      <span className="ledger-meta" data-testid={testId ? `${testId}-missing` : undefined}>
        not recorded
      </span>
    );
  }

  const raw = (value ?? "").trim();
  const relative = showRelative ? formatLedgerRelative(raw, now) : null;

  return (
    <time dateTime={raw} title={raw} suppressHydrationWarning data-testid={testId}>
      {formatted}
      {relative ? (
        <span className="ledger-meta" data-testid={testId ? `${testId}-relative` : undefined}>
          {` (${relative})`}
        </span>
      ) : null}
    </time>
  );
}
