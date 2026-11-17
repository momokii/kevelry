// Pure formatting helpers for the priority signal blocks (task 49). No DOM,
// no database: probability bar widths, signed deltas, and state labels only.

import { describe, expect, it } from "vitest";

import {
  CWE_TAXONOMY_UNAVAILABLE,
  CWE_UNMAPPED_STATE,
  cweMitigationLabel,
  cvssBandForScore,
  cvssStateForRow,
  epssBarWidthPercent,
  formatSignedDeltaPp,
  kevStateText,
} from "../src/components/priority/PriorityView";
import type { CweRef } from "../src/lib/cwe-catalog";
import { KEV_RANSOMWARE_USE_LABELS, cweChipName, cweMitigations } from "../src/lib/cwe-display";

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

describe("cweChipName", () => {
  it("returns the published name only for known ids", () => {
    const known: CweRef = {
      id: "CWE-79",
      status: "known",
      name: " Improper Neutralization of Input During Web Page Generation ",
      url: "https://cwe.mitre.org/data/definitions/79.html",
    };
    expect(cweChipName(known)).toBe("Improper Neutralization of Input During Web Page Generation");
    expect(
      cweChipName({ id: "CWE-78", status: "known", url: "https://example.org" }),
      "a known entry with no published name claims none",
    ).toBeNull();
    expect(
      cweChipName({ id: "CWE-78", status: "known", name: "   ", url: "https://example.org" }),
      "whitespace is not a name",
    ).toBeNull();
  });

  it("never invents a name for unmapped or unavailable ids", () => {
    expect(
      cweChipName({
        id: "CWE-999999",
        status: "unmapped",
        name: "Should not render",
        url: "https://cwe.mitre.org/data/definitions/999999.html",
      }),
    ).toBeNull();
    expect(
      cweChipName({
        id: "CWE-79",
        status: "taxonomy-unavailable",
        url: "https://cwe.mitre.org/data/definitions/79.html",
      }),
    ).toBeNull();
  });

  it("states its own words for the two degraded states", () => {
    expect(CWE_UNMAPPED_STATE).toBe("not in the loaded catalog");
    expect(CWE_TAXONOMY_UNAVAILABLE).toBe("taxonomy unavailable");
  });
});

describe("cweMitigations", () => {
  it("discloses only known, non-empty mitigation text in order", () => {
    const cwes: CweRef[] = [
      { id: "CWE-78", status: "known", name: "A", mitigation: "Escape arguments.", url: "u" },
      { id: "CWE-79", status: "unmapped", mitigation: "not ours", url: "u" },
      { id: "CWE-89", status: "known", name: "B", url: "u" },
      { id: "CWE-94", status: "taxonomy-unavailable", url: "u" },
      { id: "CWE-20", status: "known", name: "C", mitigation: "   ", url: "u" },
    ];
    expect(cweMitigations(cwes)).toEqual([{ id: "CWE-78", mitigation: "Escape arguments." }]);
    expect(cweMitigations([])).toEqual([]);
  });
});

describe("cweMitigationLabel", () => {
  it("names the catalog version from the payload, never a hard-coded one", () => {
    expect(cweMitigationLabel("1000-956")).toBe("Mitigation (reference, MITRE CWE 1000-956)");
    expect(cweMitigationLabel("1000-2")).toBe("Mitigation (reference, MITRE CWE 1000-2)");
  });

  it("does not invent a version when the payload carries none", () => {
    expect(cweMitigationLabel(null)).toBe("Mitigation (reference, MITRE CWE)");
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
  it("gives both membership states a word, and the negative case a scope", () => {
    expect(kevStateText(true)).toBe("Listed");
    expect(kevStateText(false)).toBe("Not listed");
  });
});

describe("KEV_RANSOMWARE_USE_LABELS", () => {
  it("keeps the catalog's tri-state wording distinct and never negated", () => {
    expect(KEV_RANSOMWARE_USE_LABELS).toEqual({
      known: "Known (catalog)",
      unknown: "Unknown (catalog)",
      unstated: "Not stated",
    });
    expect(KEV_RANSOMWARE_USE_LABELS.unknown).not.toBe(KEV_RANSOMWARE_USE_LABELS.unstated);
    for (const label of Object.values(KEV_RANSOMWARE_USE_LABELS)) {
      expect(label.toLowerCase()).not.toMatch(/no (known )?ransomware|not ransomware/);
    }
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
