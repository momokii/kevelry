import { describe, expect, it } from "vitest";

import {
  FORECAST_VIEW_HREF,
  KEV_VIEW_HREF,
  buildVolumeSeries,
  dayExploreHref,
  epssBucketLabel,
  formatCount,
  monthLabel,
  nextDayString,
  monthExploreHref,
  monthlyVolume,
  percentOf,
  publishedShare,
  severityExploreHref,
  severityRows,
  shareText,
  trailingDaysFrom,
} from "../src/components/overview/chartData";

describe("nextDayString", () => {
  it("advances one UTC day across month and year edges", () => {
    expect(nextDayString("2026-10-24")).toBe("2026-10-25");
    expect(nextDayString("2026-01-31")).toBe("2026-02-01");
    expect(nextDayString("2025-12-31")).toBe("2026-01-01");
  });

  it("rejects non-days instead of wrapping them", () => {
    expect(nextDayString("2026-02-30")).toBeNull();
    expect(nextDayString("not-a-day")).toBeNull();
    expect(nextDayString("2026-10-24T12:00:00Z")).toBeNull();
  });
});

describe("dayExploreHref", () => {
  it("builds a half-open UTC day window for click-through", () => {
    expect(dayExploreHref("2026-10-24")).toBe("/explore?dateStart=2026-10-24&dateEnd=2026-10-25");
    expect(dayExploreHref("2025-12-31")).toBe("/explore?dateStart=2025-12-31&dateEnd=2026-01-01");
  });

  it("falls back to unfiltered explore for invalid days", () => {
    expect(dayExploreHref("bogus")).toBe("/explore");
  });
});

describe("severityExploreHref", () => {
  it("targets the band Explore accepts", () => {
    for (const band of ["critical", "high", "medium", "low", "none", "legacy", "unknown"]) {
      expect(severityExploreHref(band)).toBe(`/explore?severity=${band}`);
    }
  });
});

describe("priority view hrefs", () => {
  it("point at the named views, never a fabricated range filter", () => {
    expect(KEV_VIEW_HREF).toBe("/priority?view=known-exploited");
    expect(FORECAST_VIEW_HREF).toBe("/priority?view=highest-forecast");
  });
});

describe("trailingDaysFrom and buildVolumeSeries", () => {
  it("returns the 30-day window ending on the anchor day", () => {
    const days = trailingDaysFrom("2026-10-24", 30);
    expect(days).toHaveLength(30);
    expect(days[0]).toBe("2026-09-25");
    expect(days[29]).toBe("2026-10-24");
  });

  it("fills missing days with zero instead of dropping them", () => {
    const series = buildVolumeSeries({ "2026-10-24": 5 }, "2026-10-24", 3);
    expect(series).toEqual([
      { bucketStart: "2026-10-22", count: 0 },
      { bucketStart: "2026-10-23", count: 0 },
      { bucketStart: "2026-10-24", count: 5 },
    ]);
  });

  it("returns an empty series without an anchor day", () => {
    expect(buildVolumeSeries({}, null, 30)).toEqual([]);
    expect(trailingDaysFrom(null, 30)).toEqual([]);
  });
});

describe("shareText and percentOf", () => {
  it("always pairs a percentage with its denominator", () => {
    const text = shareText(45, 395286);
    expect(text).toContain("45");
    expect(text).toContain("395,286");
    expect(text).toContain("published");
    expect(text).toMatch(/\(.*%\)/);
  });

  it("renders empty buckets as honest zeros, never NaN shares", () => {
    expect(shareText(0, 395286)).toBe("0 in this interval");
    expect(percentOf(0, 0)).toBeNull();
    expect(shareText(3, 0)).toContain("3 of 0 published");
    expect(shareText(3, 0)).not.toContain("%");
  });

  it("formats whole-cohort shares without decimals", () => {
    expect(percentOf(100, 100)).toBe("100%");
  });

  it("names the population a share is computed against", () => {
    expect(publishedShare(0, 0, "scored forecasts")).toBe("0 of 0 scored forecasts");
    expect(publishedShare(45, 395286, "KEV additions")).toContain("45 of 395,286 KEV additions");
    expect(publishedShare(4, 10, "KEV additions in this window")).toContain("(40.00%)");
  });
});

describe("formatCount", () => {
  it("groups thousands for scannable values", () => {
    expect(formatCount(395286)).toBe("395,286");
  });
});

describe("epssBucketLabel", () => {
  it("labels all ten 10-point buckets with ranges", () => {
    expect(epssBucketLabel(0)).toBe("0–10%");
    expect(epssBucketLabel(9)).toBe("90–100%");
    expect(epssBucketLabel(10)).toBeNull();
    expect(epssBucketLabel(-1)).toBeNull();
  });
});

describe("severityRows", () => {
  it("keeps every band in policy order with zero defaults", () => {
    const rows = severityRows({ critical: 10, high: 20 });
    expect(rows.map((row) => row.band)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "none",
      "legacy",
      "unknown",
    ]);
    expect(rows.find((row) => row.band === "critical")).toMatchObject({
      label: "Critical",
      count: 10,
    });
    expect(rows.find((row) => row.band === "unknown")).toMatchObject({
      label: "Unscored",
      count: 0,
    });
  });
});

describe("monthLabel", () => {
  it("renders catalog months for humans and rejects bad input", () => {
    expect(monthLabel("2026-09")).toBe("Sep 2026");
    expect(monthLabel("2026-13")).toBeNull();
    expect(monthLabel("September")).toBeNull();
  });
});

describe("monthly volume", () => {
  it("groups daily counts into the trailing months ending at the anchor", () => {
    const counts = new Map([
      ["2026-08-01", 4],
      ["2026-08-31", 6],
      ["2026-09-15", 5],
      ["2026-10-02", 7],
      ["2025-01-01", 99],
    ]);
    expect(monthlyVolume(counts, "2026-10-21", 3)).toEqual([
      { bucketStart: "2026-08", count: 10 },
      { bucketStart: "2026-09", count: 5 },
      { bucketStart: "2026-10", count: 7 },
    ]);
  });

  it("returns an empty series without a valid anchor", () => {
    expect(monthlyVolume(new Map(), null, 3)).toEqual([]);
    expect(monthlyVolume(new Map(), "not-a-day", 3)).toEqual([]);
  });

  it("builds month ranges that roll over the year", () => {
    expect(monthExploreHref("2026-10")).toBe("/explore?dateStart=2026-10-01&dateEnd=2026-11-01");
    expect(monthExploreHref("2026-12")).toBe("/explore?dateStart=2026-12-01&dateEnd=2027-01-01");
    expect(monthExploreHref("2026-13")).toBeNull();
  });
});
