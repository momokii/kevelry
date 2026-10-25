// Pure formatting helpers for the priority signal blocks (task 49). No DOM,
// no database: probability bar widths, signed deltas, and state labels only.

import { describe, expect, it } from "vitest";

import {
  cvssBandForScore,
  cvssStateForRow,
  epssBarWidthPercent,
  formatSignedDeltaPp,
  kevStateText,
} from "../src/components/priority/PriorityView";

describe("epssBarWidthPercent", () => {
  it("passes the real percentage through for the bar width", () => {
    expect(epssBarWidthPercent("74.64")).toBeCloseTo(74.64, 5);
    expect(epssBarWidthPercent("0")).toBe(0);
    expect(epssBarWidthPercent("100")).toBe(100);
  });

  it("clamps out-of-range input instead of overflowing the bar", () => {
    expect(epssBarWidthPercent("140.2")).toBe(100);
    expect(epssBarWidthPercent("-3")).toBe(0);
  });

  it("returns null for unknown or unparseable input, never 0", () => {
    expect(epssBarWidthPercent(null)).toBeNull();
    expect(epssBarWidthPercent("")).toBeNull();
    expect(epssBarWidthPercent("unavailable")).toBeNull();
  });
});

describe("formatSignedDeltaPp", () => {
  it("restores the rising sign on plain magnitudes", () => {
    expect(formatSignedDeltaPp("8")).toBe("+8 percentage points");
    expect(formatSignedDeltaPp("1")).toBe("+1 percentage points");
  });

  it("keeps an explicit sign instead of doubling it", () => {
    expect(formatSignedDeltaPp("+8")).toBe("+8 percentage points");
    expect(formatSignedDeltaPp("-2")).toBe("-2 percentage points");
  });

  it("returns null for missing or non-numeric input, never zero", () => {
    expect(formatSignedDeltaPp(null)).toBeNull();
    expect(formatSignedDeltaPp("")).toBeNull();
    expect(formatSignedDeltaPp("  ")).toBeNull();
    expect(formatSignedDeltaPp("n/a")).toBeNull();
  });
});

describe("cvssBandForScore", () => {
  it("maps the published v3.x/v4.0 ranges to band words", () => {
    expect(cvssBandForScore("9.8")).toBe("critical");
    expect(cvssBandForScore("9.0")).toBe("critical");
    expect(cvssBandForScore("8.5")).toBe("high");
    expect(cvssBandForScore("7.0")).toBe("high");
    expect(cvssBandForScore("5.5")).toBe("medium");
    expect(cvssBandForScore("4.0")).toBe("medium");
    expect(cvssBandForScore("3.9")).toBe("low");
    expect(cvssBandForScore("0.0")).toBe("low");
  });

  it("returns null for missing or non-numeric input", () => {
    expect(cvssBandForScore(null)).toBeNull();
    expect(cvssBandForScore("")).toBeNull();
    expect(cvssBandForScore("unscored")).toBeNull();
  });
});

describe("kevStateText", () => {
  it("keeps the exact listed wording and names the snapshot scope otherwise", () => {
    expect(kevStateText(true)).toBe("KEV listed");
    expect(kevStateText(false)).toBe("Not listed in this KEV snapshot.");
  });
});

describe("cvssStateForRow", () => {
  it("prefers known over legacy, and ADP-only over unscored", () => {
    expect(
      cvssStateForRow({ primaryKnown: true, primaryLegacy: false, primaryAdpOnly: true }),
    ).toBe("known");
    expect(
      cvssStateForRow({ primaryKnown: false, primaryLegacy: true, primaryAdpOnly: false }),
    ).toBe("legacy");
    expect(
      cvssStateForRow({ primaryKnown: false, primaryLegacy: false, primaryAdpOnly: true }),
    ).toBe("adp-only");
    expect(
      cvssStateForRow({ primaryKnown: false, primaryLegacy: false, primaryAdpOnly: false }),
    ).toBe("unscored");
  });
});
