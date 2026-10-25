import { describe, expect, it } from "vitest";

import { formatLedgerRelative, formatLedgerTime } from "../src/components/ledger/TimeText";

const INSTANT = "2026-10-25T05:14:00.000Z";

describe("formatLedgerTime", () => {
  it("renders the fixed instant per zone with pinned abbreviations", () => {
    expect(formatLedgerTime(INSTANT, "Asia/Jakarta")).toBe("25 Oct 2026, 12:14 WIB");
    expect(formatLedgerTime(INSTANT, "Asia/Singapore")).toBe("25 Oct 2026, 13:14 SGT");
    expect(formatLedgerTime(INSTANT, "UTC")).toBe("25 Oct 2026, 05:14 UTC");
    expect(formatLedgerTime(INSTANT, "Europe/London")).toBe("25 Oct 2026, 05:14 GMT");
    expect(formatLedgerTime(INSTANT, "America/New_York")).toBe("25 Oct 2026, 01:14 EDT");
    expect(formatLedgerTime(INSTANT, "America/Los_Angeles")).toBe("24 Oct 2026, 22:14 PDT");
  });

  it("is DST-safe across seasons", () => {
    expect(formatLedgerTime("2026-01-15T12:00:00.000Z", "America/New_York")).toBe(
      "15 Jan 2026, 07:00 EST",
    );
    expect(formatLedgerTime("2026-07-15T12:00:00.000Z", "America/New_York")).toBe(
      "15 Jul 2026, 08:00 EDT",
    );
    expect(formatLedgerTime("2026-01-15T12:00:00.000Z", "Europe/London")).toBe(
      "15 Jan 2026, 12:00 GMT",
    );
    expect(formatLedgerTime("2026-07-15T12:00:00.000Z", "Europe/London")).toBe(
      "15 Jul 2026, 13:00 BST",
    );
  });

  it("renders date-only input as a calendar date", () => {
    expect(formatLedgerTime("2026-10-24", "Asia/Jakarta")).toBe("24 Oct 2026");
    expect(formatLedgerTime("2026-10-24", "America/New_York")).toBe("24 Oct 2026");
  });

  it("returns null for missing or invalid input", () => {
    expect(formatLedgerTime(null, "Asia/Jakarta")).toBeNull();
    expect(formatLedgerTime(undefined, "Asia/Jakarta")).toBeNull();
    expect(formatLedgerTime("", "Asia/Jakarta")).toBeNull();
    expect(formatLedgerTime("   ", "Asia/Jakarta")).toBeNull();
    expect(formatLedgerTime("not-a-date", "Asia/Jakarta")).toBeNull();
    expect(formatLedgerTime("2026-13-40", "Asia/Jakarta")).toBeNull();
  });

  it("falls back to UTC for an unknown zone", () => {
    expect(formatLedgerTime(INSTANT, "Mars/Olympus")).toBe("25 Oct 2026, 05:14 UTC");
  });
});

describe("formatLedgerRelative", () => {
  const now = Date.parse(INSTANT) + (2 * 60 + 14) * 60 * 1000;

  it("renders hours, minutes, and just-now forms", () => {
    expect(formatLedgerRelative(INSTANT, now)).toBe("2 hours ago");
    expect(formatLedgerRelative(INSTANT, Date.parse(INSTANT) + 60 * 1000)).toBe("1 minute ago");
    expect(formatLedgerRelative(INSTANT, Date.parse(INSTANT) + 30 * 1000)).toBe("just now");
    expect(formatLedgerRelative(INSTANT, Date.parse(INSTANT) + 3 * 24 * 60 * 60 * 1000)).toBe(
      "3 days ago",
    );
  });

  it("renders future instants without crashing", () => {
    expect(formatLedgerRelative(INSTANT, Date.parse(INSTANT) - 3 * 24 * 60 * 60 * 1000)).toBe(
      "in 3 days",
    );
  });

  it("returns null for date-only and invalid input", () => {
    expect(formatLedgerRelative("2026-10-24", now)).toBeNull();
    expect(formatLedgerRelative("not-a-date", now)).toBeNull();
    expect(formatLedgerRelative(null, now)).toBeNull();
  });
});
