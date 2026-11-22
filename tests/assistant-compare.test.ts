// Compare: two ids in, one fixed field-by-field question out.
//
// The question is asserted as a whole property, not a snapshot: it must name
// every field in COMPARE_FIELDS, and it must keep the three behaviours a
// comparison loses most easily — no omitted field, an explicit "missing from the
// dataset", and no fused score or winner.

import { describe, expect, it } from "vitest";

import {
  COMPARE_EMPTY_MESSAGE,
  COMPARE_FIELDS,
  COMPARE_SAME_MESSAGE,
  COMPARE_SHAPE_MESSAGE,
  buildCompareQuestion,
  normalizeCveId,
  validateCompareField,
  validateComparePair,
} from "../src/components/assistant/assistant-compare";

describe("compare field validation", () => {
  it("[CODE] accepts CVE-YYYY-NNNN and normalises case and whitespace", () => {
    expect(validateCompareField("  cve-2021-44228 ")).toBeNull();
    expect(normalizeCveId(" cve-2021-44228 ")).toBe("CVE-2021-44228");
  });

  it("[CODE] asks for an id when the field is empty", () => {
    expect(validateCompareField("   ")).toBe(COMPARE_EMPTY_MESSAGE);
  });

  it("[CODE] demands the exact shape for anything else", () => {
    for (const raw of ["CVE-21-44228", "CVE-2021-442", "2021-44228", "CVE-2021-44228x"]) {
      expect(validateCompareField(raw)).toBe(COMPARE_SHAPE_MESSAGE);
    }
  });
});

describe("compare pair validation", () => {
  it("[CODE] returns the normalised pair when both fields are valid and distinct", () => {
    expect(validateComparePair("cve-2021-44228", " CVE-2021-45046 ")).toEqual({
      ok: true,
      pair: { a: "CVE-2021-44228", b: "CVE-2021-45046" },
    });
  });

  it("[CODE] reports each invalid field separately", () => {
    const result = validateComparePair("", "not-an-id");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.a).toBe(COMPARE_EMPTY_MESSAGE);
    expect(result.errors.b).toBe(COMPARE_SHAPE_MESSAGE);
  });

  it("[CODE] refuses the same record twice", () => {
    const result = validateComparePair("CVE-2021-44228", "cve-2021-44228");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.errors.a).toBeNull();
    expect(result.errors.b).toBe(COMPARE_SAME_MESSAGE);
  });
});

describe("compare question", () => {
  const question = buildCompareQuestion({ a: "CVE-2021-44228", b: "CVE-2021-45046" });

  it("[CODE] names both records", () => {
    expect(question).toContain("CVE-2021-44228");
    expect(question).toContain("CVE-2021-45046");
    expect(question.startsWith("Compare CVE-2021-44228 and CVE-2021-45046")).toBe(true);
  });

  it("[CODE] names every field in the fixed order", () => {
    for (const field of COMPARE_FIELDS) expect(question).toContain(field);
    expect(question.indexOf("status")).toBeLessThan(question.indexOf("publication date"));
    expect(question.indexOf("KEV membership")).toBeLessThan(question.indexOf("ransomware use"));
    expect(question.indexOf("latest EPSS")).toBeLessThan(question.indexOf("CWE list"));
  });

  it("[CODE] forbids omitting a field or guessing a missing one", () => {
    expect(question).toContain("without omitting one");
    expect(question).toContain("say that it is missing from the dataset for that record");
    expect(question).toContain("instead of leaving the field out or guessing");
  });

  it("[CODE] forbids a fused score and a winner", () => {
    expect(question).toContain("Do not combine the signals into one score");
    expect(question).toContain("do not name a winner");
  });
});
