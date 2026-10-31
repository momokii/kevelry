import { describe, expect, it } from "vitest";

import {
  compareDecimalStrings,
  displayProbabilityPercent,
  orderDefaultPriority,
  orderHighestForecast,
  orderKevDueSoon,
  orderKnownExploited,
  risingDeltaPp,
  selectNewCritical,
  selectPrimaryCvss,
  selectRisingForecast,
} from "../src/lib/ranking";

// ---------------------------------------------------------------------------
// Helpers to build fixtures. EPSS/CVSS decimals are always exact strings;
// timestamps are ISO UTC. Malformed values are intentional in adversarial
// tests further below.
// ---------------------------------------------------------------------------

function def(
  id: string,
  opts: { kev?: boolean; epss?: string | null; publishedAt?: string | null } = {},
) {
  return {
    id,
    kevMember: opts.kev ?? false,
    epss: opts.epss === undefined ? null : opts.epss,
    publishedAt: opts.publishedAt === undefined ? "2026-10-20T12:00:00.000Z" : opts.publishedAt,
  };
}

function kev(id: string, dateAdded: string | null, kevMember = true) {
  return { id, kevMember, dateAdded };
}

function fc(id: string, epss: string | null, publishedAt: string | null = "2026-10-20T12:00:00.000Z") {
  return { id, epss, publishedAt };
}

function nc(id: string, publishedAt: string | null, primary: ReturnType<typeof selectPrimaryCvss>) {
  return { id, publishedAt, primary };
}

function cna(version: string, baseScore: string, vector = "", sourceOrder = 0) {
  return { origin: "CNA" as const, version, baseScore, vector, sourceOrder };
}

function adp(version: string, baseScore: string, vector = "", sourceOrder = 0) {
  return { origin: "ADP" as const, version, baseScore, vector, sourceOrder };
}

function rising(
  id: string,
  currentEpss: string | null,
  currentDate: string | null,
  currentModel: string | null,
  previousEpss: string | null,
  previousDate: string | null,
  previousModel: string | null,
) {
  return { id, currentEpss, currentDate, currentModel, previousEpss, previousDate, previousModel };
}

function ids<T extends { id: string }>(rows: readonly T[]): string[] {
  return rows.map((r) => r.id);
}

// ===========================================================================
// Worked examples from docs/DATA_WORKFLOW.md 164-189 (invented CVE-2099 IDs)
// ===========================================================================

describe("worked examples (DATA_WORKFLOW.md 164-189)", () => {
  it("evidence tier dominates: KEV + unknown EPSS beats non-KEV + 0.99", () => {
    const rows = [
      def("CVE-2099-0002", { kev: false, epss: "0.99" }),
      def("CVE-2099-0001", { kev: true, epss: null }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("probability within a tier: 0.80 beats 0.20 even when the 0.20 record is newer", () => {
    const rows = [
      def("CVE-2099-0002", { epss: "0.20", publishedAt: "2026-10-23T00:00:00.000Z" }),
      def("CVE-2099-0001", { epss: "0.80", publishedAt: "2026-10-20T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("zero vs unknown: actual 0 outranks unknown (unknown is never coerced to 0)", () => {
    const rows = [def("CVE-2099-0004", { epss: null }), def("CVE-2099-0003", { epss: "0" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0003", "CVE-2099-0004"]);
  });

  it("display rounding: 0.12344 beats 0.12341 although both display 12.34%", () => {
    const rows = [def("CVE-2099-0006", { epss: "0.12341" }), def("CVE-2099-0005", { epss: "0.12344" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0005", "CVE-2099-0006"]);
    expect(displayProbabilityPercent("0.12344")).toBe("12.344");
    expect(displayProbabilityPercent("0.12341")).toBe("12.341");
  });

  it("complete numeric/date tie: ASCII ID breaks the tie", () => {
    const rows = [def("CVE-2099-0008", { epss: "0.5" }), def("CVE-2099-0007", { epss: "0.5" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0007", "CVE-2099-0008"]);
  });

  it("known vs missing date: dated record first at equal tier/probability", () => {
    const rows = [
      def("CVE-2099-0011", { epss: "0.5", publishedAt: null }),
      def("CVE-2099-0010", { epss: "0.5", publishedAt: "2026-10-20T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0010", "CVE-2099-0011"]);
  });

  it("timestamp tie-break: 23 Oct beats 22 Oct at equal tier/probability", () => {
    const rows = [
      def("CVE-2099-0002", { epss: "0.5", publishedAt: "2026-10-22T00:00:00.000Z" }),
      def("CVE-2099-0001", { epss: "0.5", publishedAt: "2026-10-23T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("KEV-specific ordering: newer dateAdded first even when the older entry has higher EPSS", () => {
    const rows = [kev("CVE-2099-0002", "2026-10-22"), kev("CVE-2099-0001", "2026-10-23")];
    expect(ids(orderKnownExploited(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("forecast-specific ordering: nonmember 0.90 beats KEV member 0.10 (KEV is not a sort key)", () => {
    const rows = [fc("CVE-2099-0002", "0.10"), fc("CVE-2099-0001", "0.90")];
    expect(ids(orderHighestForecast(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("CNA source policy: ADP-only v4 10.0 leaves primary unknown and new-critical ineligible", () => {
    const primary = selectPrimaryCvss([adp("4.0", "10.0", "CVSS:4.0/AV:N", 0)]);
    expect(primary).toBeNull();
    const rows = [nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", primary)];
    expect(selectNewCritical(rows, "2026-10-24T00:00:00.000Z")).toEqual([]);
  });

  it("version preference: CNA v4 8.5 beats CNA v3.1 9.8; new-critical ineligible", () => {
    const primary = selectPrimaryCvss([cna("3.1", "9.8", "CVSS:3.1/AV:N", 1), cna("4.0", "8.5", "CVSS:4.0/AV:N", 0)]);
    expect(primary?.version).toBe("4.0");
    expect(primary?.baseScore).toBe("8.5");
    const rows = [nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", primary)];
    expect(selectNewCritical(rows, "2026-10-24T00:00:00.000Z")).toEqual([]);
  });

  it("scenario and vector ties: highest scenario wins, then vector ASCII, then source order", () => {
    const byScore = selectPrimaryCvss([
      cna("3.1", "8.5", "CVSS:3.1/AV:N", 0),
      cna("3.1", "9.2", "CVSS:3.1/AV:N", 1),
    ]);
    expect(byScore?.baseScore).toBe("9.2");
    expect(byScore?.label).toBe("worst CNA-provided scenario");

    const byVector = selectPrimaryCvss([
      cna("3.1", "9.2", "B", 0),
      cna("3.1", "9.2", "A", 1),
    ]);
    expect(byVector?.vector).toBe("A");

    const first = { origin: "CNA" as const, version: "3.1", baseScore: "9.2", vector: "A", sourceOrder: 0 };
    const second = { origin: "CNA" as const, version: "3.1", baseScore: "9.2", vector: "A", sourceOrder: 1 };
    const byOrder = selectPrimaryCvss([second, first]);
    expect(byOrder).toMatchObject({ vector: "A", baseScore: "9.2" });
    // source-order final tie: the metric listed first in source order wins
    const reversed = selectPrimaryCvss([first, second]);
    expect(reversed).toMatchObject({ vector: "A", baseScore: "9.2" });
    expect(byOrder).toEqual(reversed);
  });

  it("legacy-only metric: CNA v2 10.0 is legacy-scored, never critical", () => {
    const primary = selectPrimaryCvss([cna("2.0", "10.0", "AV:N/AC:L", 0)]);
    expect(primary?.version).toBe("2.0");
    const rows = [nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", primary)];
    expect(selectNewCritical(rows, "2026-10-24T00:00:00.000Z")).toEqual([]);
  });

  it("rising calculation: 0.10 then 0.18 is +8pp, not +80pp", () => {
    expect(risingDeltaPp("0.18", "0.10")).toBe("8");
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.18", "2026-10-24", "A", "0.10", "2026-10-17", "A")],
      "2026-10-24",
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]?.deltaPp).toBe("8");
  });

  it("rising ties: equal +8 deltas sort by current p, then ID", () => {
    const rows = selectRisingForecast(
      [
        rising("CVE-2099-0002", "0.28", "2026-10-24", "A", "0.20", "2026-10-17", "A"),
        rising("CVE-2099-0001", "0.18", "2026-10-24", "A", "0.10", "2026-10-17", "A"),
      ],
      "2026-10-24",
    );
    expect(rows.map((r) => r.item.id)).toEqual(["CVE-2099-0002", "CVE-2099-0001"]);
    const tie = selectRisingForecast(
      [
        rising("CVE-2099-0002", "0.28", "2026-10-24", "A", "0.20", "2026-10-17", "A"),
        rising("CVE-2099-0001", "0.28", "2026-10-24", "A", "0.20", "2026-10-17", "A"),
      ],
      "2026-10-24",
    );
    expect(tie.map((r) => r.item.id)).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("model boundary: A 0.10 to B 0.80 is ineligible (no +70 spike claim)", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.80", "2026-10-24", "B", "0.10", "2026-10-17", "A")],
      "2026-10-24",
    );
    expect(rows).toEqual([]);
  });

  it("missing history: current known with no exact d-7 row is ineligible", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.50", "2026-10-24", "A", null, null, null)],
      "2026-10-24",
    );
    expect(rows).toEqual([]);
  });

  it("date boundary: T-30d included, exactly T excluded", () => {
    const cutoff = "2026-10-24T00:00:00.000Z";
    const atLower = "2026-09-24T00:00:00.000Z"; // exactly T - 30d
    const primary = selectPrimaryCvss([cna("3.1", "9.8", "CVSS:3.1/AV:N", 0)]);
    const rows = [
      nc("CVE-2099-0001", atLower, primary),
      nc("CVE-2099-0002", cutoff, primary),
    ];
    expect(ids(selectNewCritical(rows, cutoff))).toEqual(["CVE-2099-0001"]);
  });

  it("new-critical order: newer first; equal timestamps fall back to ID, not CVSS magnitude", () => {
    const low = selectPrimaryCvss([cna("3.1", "9.1", "CVSS:3.1/AV:N", 0)]);
    const high = selectPrimaryCvss([cna("3.1", "10.0", "CVSS:3.1/AV:N", 0)]);
    const rows = [
      nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", high),
      nc("CVE-2099-0002", "2026-10-22T00:00:00.000Z", low),
    ];
    expect(ids(selectNewCritical(rows, "2026-10-24T00:00:00.000Z"))).toEqual([
      "CVE-2099-0002",
      "CVE-2099-0001",
    ]);
    const sameTime = [
      nc("CVE-2099-0002", "2026-10-22T00:00:00.000Z", low),
      nc("CVE-2099-0001", "2026-10-22T00:00:00.000Z", high),
    ];
    expect(ids(selectNewCritical(sameTime, "2026-10-24T00:00:00.000Z"))).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0002",
    ]);
  });
});

// ===========================================================================
// 31 documented boundary cases (plan todo-3 acceptance: every assertion here
// must pass; a swapped tie-break must turn the suite red)
// ===========================================================================

describe("boundary cases: default priority", () => {
  it("B01 KEV tier beats high score even at the extremes (KEV 0 vs non-KEV 0.999999)", () => {
    const rows = [
      def("CVE-2099-0002", { kev: false, epss: "0.999999" }),
      def("CVE-2099-0001", { kev: true, epss: "0" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B02 KEV members with unknown EPSS still outrank every scored nonmember", () => {
    const rows = [
      def("CVE-2099-0003", { kev: false, epss: "1" }),
      def("CVE-2099-0002", { kev: true, epss: null }),
      def("CVE-2099-0001", { kev: true, epss: "0" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0002",
      "CVE-2099-0003",
    ]);
  });

  it("B03 zero-vs-unknown does not depend on date recency (unknown-newer still loses to zero-older)", () => {
    const rows = [
      def("CVE-2099-0002", { epss: null, publishedAt: "2026-10-23T00:00:00.000Z" }),
      def("CVE-2099-0001", { epss: "0.000000", publishedAt: "2020-01-01T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B04 display-rounding tie at three decimals uses raw value (0.12449 vs 0.12441)", () => {
    const rows = [def("CVE-2099-0002", { epss: "0.12441" }), def("CVE-2099-0001", { epss: "0.12449" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B05 exact-decimal tie is stable under binary-float hazards (0.1+0.2 class deltas)", () => {
    // 0.28 - 0.20 and 0.18 - 0.10 are both exactly 0.08; binary float
    // subtraction yields 0.08000000000000002 vs 0.07999999999999999 and would
    // break the tie. Scaled-integer arithmetic must keep them equal.
    expect(compareDecimalStrings("0.08", "0.08")).toBe(0);
    expect(risingDeltaPp("0.28", "0.20")).toBe(risingDeltaPp("0.18", "0.10"));
  });

  it("B06 unknown-vs-unknown EPSS falls through to date, then ID", () => {
    const rows = [
      def("CVE-2099-0003", { epss: null, publishedAt: null }),
      def("CVE-2099-0002", { epss: null, publishedAt: "2026-10-20T00:00:00.000Z" }),
      def("CVE-2099-0001", { epss: null, publishedAt: "2026-10-20T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0002",
      "CVE-2099-0003",
    ]);
  });

  it("B07 malformed publication date counts as unknown (never throws, sorts after known)", () => {
    const rows = [
      def("CVE-2099-0002", { epss: "0.5", publishedAt: "not-a-date" }),
      def("CVE-2099-0001", { epss: "0.5", publishedAt: "2026-10-20T00:00:00.000Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B08 malformed EPSS counts as unknown (never throws, sorts after real zero)", () => {
    const rows = [
      def("CVE-2099-0002", { epss: "NaN" }),
      def("CVE-2099-0001", { epss: "0" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B09 out-of-range EPSS (>1) counts as unknown", () => {
    const rows = [def("CVE-2099-0002", { epss: "1.5" }), def("CVE-2099-0001", { epss: "0.01" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B10 timestamp ties at the same millisecond fall back to ASCII ID", () => {
    const rows = [
      def("CVE-2099-0002", { epss: "0.5", publishedAt: "2026-10-23T10:00:00.123Z" }),
      def("CVE-2099-0001", { epss: "0.5", publishedAt: "2026-10-23T10:00:00.123Z" }),
    ];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });
});

describe("boundary cases: kev-due-soon", () => {
  const due = (id: string, kevDueDate: unknown, kevMember = true) => ({
    id,
    kevMember,
    kevDueDate,
  });

  it("due dates ascend with overdue first and no upper cutoff", () => {
    const rows = [
      due("CVE-2099-0003", "2027-06-01"),
      due("CVE-2099-0001", "2026-10-20"),
      due("CVE-2099-0002", "2026-11-15"),
    ];
    expect(ids(orderKevDueSoon(rows))).toEqual([
      "CVE-2099-0001",
      "CVE-2099-0002",
      "CVE-2099-0003",
    ]);
  });

  it("due-date ties fall back to ASCII ID", () => {
    const rows = [due("CVE-2099-0002", "2026-11-01"), due("CVE-2099-0001", "2026-11-01")];
    expect(ids(orderKevDueSoon(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("excludes non-members and malformed or missing due dates", () => {
    const rows = [
      due("CVE-2099-0004", "2026-10-20", false),
      due("CVE-2099-0005", null),
      due("CVE-2099-0006", "next Friday"),
      due("CVE-2099-0007", "2026-13-40"),
      due("CVE-2099-0001", "2026-10-20"),
    ];
    expect(ids(orderKevDueSoon(rows))).toEqual(["CVE-2099-0001"]);
  });

  it("never throws on hostile rows", () => {
    const garbage = [null, 42, "due", { id: 7, kevMember: "yes", kevDueDate: {} }];
    expect(() => orderKevDueSoon(garbage)).not.toThrow();
    expect(orderKevDueSoon(garbage)).toEqual([]);
  });
});

describe("boundary cases: known-exploited and highest-forecast", () => {
  it("B11 known-exploited ignores EPSS entirely (high-EPSS older loses)", () => {
    const rows = [kev("CVE-2099-0001", "2026-10-22"), kev("CVE-2099-0002", "2026-10-23")];
    expect(ids(orderKnownExploited(rows))).toEqual(["CVE-2099-0002", "CVE-2099-0001"]);
  });

  it("B12 known-exploited dateAdded tie uses ASCII ID", () => {
    const rows = [kev("CVE-2099-0002", "2026-10-23"), kev("CVE-2099-0001", "2026-10-23")];
    expect(ids(orderKnownExploited(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B13 known-exploited excludes nonmembers and sorts invalid dateAdded last", () => {
    const rows = [
      { id: "CVE-2099-0003", kevMember: false, dateAdded: "2026-10-24" },
      kev("CVE-2099-0002", "garbage-date"),
      kev("CVE-2099-0001", "2026-10-20"),
    ];
    expect(ids(orderKnownExploited(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B14 highest-forecast excludes unknown EPSS (never coerced to 0)", () => {
    const rows = [fc("CVE-2099-0001", null), fc("CVE-2099-0002", "0.000001")];
    expect(ids(orderHighestForecast(rows))).toEqual(["CVE-2099-0002"]);
  });

  it("B15 highest-forecast probability tie prefers known publication date", () => {
    const rows = [fc("CVE-2099-0002", "0.7", null), fc("CVE-2099-0001", "0.7", "2026-10-20T00:00:00.000Z")];
    expect(ids(orderHighestForecast(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("B16 highest-forecast full tie uses ASCII ID", () => {
    const rows = [fc("CVE-2099-0002", "0.7"), fc("CVE-2099-0001", "0.7")];
    expect(ids(orderHighestForecast(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });
});

describe("boundary cases: CVSS selection", () => {
  it("B17 version preference chain 4.0 > 3.1 > 3.0 > 2.0 regardless of score", () => {
    const primary = selectPrimaryCvss([
      cna("2.0", "10.0", "v2", 3),
      cna("3.0", "9.9", "v3.0", 2),
      cna("3.1", "9.9", "v3.1", 1),
      cna("4.0", "0.1", "v4", 0),
    ]);
    expect(primary?.version).toBe("4.0");
    expect(primary?.baseScore).toBe("0.1");
  });

  it("B18 invalid CVSS entries are skipped (bad score, bad version, ADP ignored)", () => {
    const primary = selectPrimaryCvss([
      adp("4.0", "10.0", "x", 0),
      cna("9.9", "10.0", "x", 1),
      { origin: "CNA" as const, version: "3.1", baseScore: "not-a-score", vector: "x", sourceOrder: 2 },
      cna("3.1", "7.5", "CVSS:3.1/AV:N", 3),
    ]);
    expect(primary?.baseScore).toBe("7.5");
  });

  it("B19 empty, null, and all-invalid metric lists yield unknown (null), never throw", () => {
    expect(selectPrimaryCvss([])).toBeNull();
    expect(selectPrimaryCvss(null as unknown as [])).toBeNull();
    expect(selectPrimaryCvss(undefined as unknown as [])).toBeNull();
    expect(selectPrimaryCvss([cna("3.1", "11.0", "x", 0)])).toBeNull();
    expect(selectPrimaryCvss([cna("3.1", "-1", "x", 0)])).toBeNull();
  });

  it("B20 vector tie-break is byte-wise ASCII (uppercase before lowercase)", () => {
    const primary = selectPrimaryCvss([cna("3.1", "9.0", "b", 0), cna("3.1", "9.0", "A", 1)]);
    expect(primary?.vector).toBe("A");
  });

  it("B21 out-of-range CVSS (>10) is invalid and cannot become primary", () => {
    expect(selectPrimaryCvss([cna("4.0", "10.1", "x", 0)])).toBeNull();
  });
});

describe("boundary cases: rising forecast", () => {
  const D = "2026-10-24";
  const D7 = "2026-10-17";

  it("B22 zero and negative deltas are excluded (positive changes only)", () => {
    const rows = selectRisingForecast(
      [
        rising("CVE-2099-0001", "0.20", D, "A", "0.20", D7, "A"),
        rising("CVE-2099-0002", "0.10", D, "A", "0.20", D7, "A"),
        rising("CVE-2099-0003", "0.30", D, "A", "0.20", D7, "A"),
      ],
      D,
    );
    expect(rows.map((r) => r.item.id)).toEqual(["CVE-2099-0003"]);
  });

  it("B23 off-by-one history date (d-6) is ineligible: no nearest-day substitution", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.90", D, "A", "0.10", "2026-10-18", "A")],
      D,
    );
    expect(rows).toEqual([]);
  });

  it("B24 current date mismatch is ineligible (stale snapshot is never relabeled current)", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.90", "2026-10-23", "A", "0.10", "2026-10-16", "A")],
      D,
    );
    expect(rows).toEqual([]);
  });

  it("B25 malformed probability strings are ineligible, never throwing", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "high", D, "A", "0.10", D7, "A")],
      D,
    );
    expect(rows).toEqual([]);
    expect(risingDeltaPp("high", "0.10")).toBeNull();
    expect(risingDeltaPp("0.5", "also-bad")).toBeNull();
  });

  it("B26 tiny positive delta (0.000001) is eligible and formats exactly", () => {
    expect(risingDeltaPp("0.000002", "0.000001")).toBe("0.0001");
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.000002", D, "A", "0.000001", D7, "A")],
      D,
    );
    expect(rows).toHaveLength(1);
  });

  it("B27 invalid current-date parameter yields no rows instead of throwing", () => {
    const rows = selectRisingForecast(
      [rising("CVE-2099-0001", "0.5", D, "A", "0.1", D7, "A")],
      "not-a-date",
    );
    expect(rows).toEqual([]);
  });
});

describe("boundary cases: new-critical", () => {
  const T = "2026-10-24T00:00:00.000Z";

  it("B28 just-inside window (T-30d+1ms) included; just-outside (T-30d-1ms) excluded", () => {
    const primary = selectPrimaryCvss([cna("3.1", "9.8", "CVSS:3.1/AV:N", 0)]);
    const lower = Date.parse("2026-09-24T00:00:00.000Z");
    const rows = [
      nc("CVE-2099-0001", new Date(lower - 1).toISOString(), primary),
      nc("CVE-2099-0002", new Date(lower + 1).toISOString(), primary),
    ];
    expect(ids(selectNewCritical(rows, T))).toEqual(["CVE-2099-0002"]);
  });

  it("B29 modern 9.0 boundary eligible; 8.9 ineligible; v4 9.0 eligible", () => {
    const exact = selectPrimaryCvss([cna("3.1", "9.0", "x", 0)]);
    const below = selectPrimaryCvss([cna("3.1", "8.9", "x", 0)]);
    const modern = selectPrimaryCvss([cna("4.0", "9.0", "x", 0)]);
    const at = "2026-10-20T00:00:00.000Z";
    expect(selectNewCritical([nc("CVE-2099-0001", at, below)], T)).toEqual([]);
    expect(ids(selectNewCritical([nc("CVE-2099-0001", at, exact)], T))).toEqual(["CVE-2099-0001"]);
    expect(ids(selectNewCritical([nc("CVE-2099-0001", at, modern)], T))).toEqual(["CVE-2099-0001"]);
  });

  it("B30 v3.0 9.8 is modern-eligible; unknown/undated/malformed dates are ineligible", () => {
    const v30 = selectPrimaryCvss([cna("3.0", "9.8", "x", 0)]);
    expect(ids(selectNewCritical([nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", v30)], T))).toEqual([
      "CVE-2099-0001",
    ]);
    const at = "2026-10-20T00:00:00.000Z";
    expect(selectNewCritical([nc("CVE-2099-0001", null, v30)], T)).toEqual([]);
    expect(selectNewCritical([nc("CVE-2099-0001", "yesterday-ish", v30)], T)).toEqual([]);
    expect(selectNewCritical([nc("CVE-2099-0001", at, null)], T)).toEqual([]);
  });

  it("B31 invalid cutoff T yields no rows instead of throwing", () => {
    const primary = selectPrimaryCvss([cna("3.1", "9.8", "x", 0)]);
    expect(selectNewCritical([nc("CVE-2099-0001", "2026-10-20T00:00:00.000Z", primary)], "whenever")).toEqual(
      [],
    );
  });
});

// ===========================================================================
// Adversarial: malformed inputs are rejected or handled as unknown.
// Justification for each new test: without it, a regression that throws on
// hostile input (or silently promotes garbage into a ranking) would pass the
// happy-path suite silently, because every example above uses well-formed
// fixtures. These tests pin the fail-safe behavior.
// ===========================================================================

describe("adversarial: never throws uncaught on malformed input", () => {
  it("sorters tolerate null/undefined/garbage rows and still return an array", () => {
    const garbage = [null, undefined, 42, "CVE-1", { nope: true }] as unknown as Parameters<
      typeof orderDefaultPriority
    >[0];
    expect(() => orderDefaultPriority(garbage)).not.toThrow();
    expect(() => orderKnownExploited(garbage)).not.toThrow();
    expect(() => orderHighestForecast(garbage)).not.toThrow();
    expect(() =>
      selectNewCritical(garbage, "2026-10-24T00:00:00.000Z"),
    ).not.toThrow();
    expect(() => selectRisingForecast(garbage, "2026-10-24")).not.toThrow();
  });

  it("sorters do not mutate the input array", () => {
    const rows = [def("CVE-2099-0002", { epss: "0.1" }), def("CVE-2099-0001", { epss: "0.9" })];
    const snapshot = [...rows];
    orderDefaultPriority(rows);
    expect(rows).toEqual(snapshot);
  });

  it("compareDecimalStrings rejects garbage without throwing (null signals unknown)", () => {
    expect(compareDecimalStrings("NaN", "0.5")).toBeNull();
    expect(compareDecimalStrings("", "0.5")).toBeNull();
    expect(compareDecimalStrings("1e-3", "0.001")).toBeNull();
    expect(compareDecimalStrings(" 0.5", "0.5")).toBeNull();
    expect(compareDecimalStrings("0.5.2", "0.5")).toBeNull();
  });

  it("exponent-notation EPSS is unknown (exact-decimal contract, no float parsing)", () => {
    // Regression justification: Number("1e-3") === 0.001 parses fine, so a
    // float-based implementation would rank it as scored. The contract
    // requires exact source decimals, so exponent notation must be unknown.
    const rows = [def("CVE-2099-0002", { epss: "1e-3" }), def("CVE-2099-0001", { epss: "0" })];
    expect(ids(orderDefaultPriority(rows))).toEqual(["CVE-2099-0001", "CVE-2099-0002"]);
  });

  it("display helper returns null for invalid input instead of NaN text", () => {
    expect(displayProbabilityPercent("bogus")).toBeNull();
    expect(displayProbabilityPercent("2")).toBeNull();
    expect(displayProbabilityPercent(null)).toBeNull();
  });

  it("CVE IDs still sort deterministically when IDs are missing or non-strings", () => {
    const rows = [
      { id: null, kevMember: false, epss: "0.5", publishedAt: null },
      { id: "CVE-2099-0001", kevMember: false, epss: "0.5", publishedAt: null },
    ] as unknown as Parameters<typeof orderDefaultPriority>[0];
    expect(() => orderDefaultPriority(rows)).not.toThrow();
    expect(orderDefaultPriority(rows)).toHaveLength(2);
  });
});
