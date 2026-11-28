// The numeric check: the sibling of the record-id pass.
//
// What this file proves (mechanical): a figure the payloads can support
// verifies, a figure they cannot support is reported as printed, and the
// tolerance is the printed precision rather than string equality — a payload's
// `0.99999` verifies both `99.999%` and the rounded `0.9999`.
//
// Half of the work here is the negative case. A checker that accuses an honest
// answer is worse than no checker, so the guards are pinned as hard as the
// checks: list numbering, small counts, a bare year, a record id's digits, and a
// turn that read nothing at all must all produce no accusation.
//
// What this file does not prove: that a real model writes these shapes. The
// route test drives one through the production turn loop; this is the rule.

import { describe, expect, it } from "vitest";

import { extractAnswerNumbers, unverifiedAnswerNumbers } from "../src/lib/ai/numbers";
import { runRefusalTurn } from "../src/lib/ai/refusal";
import type { AssistantEvent } from "../src/lib/ai/turn";

/** A payload shaped like a real tool result, so the walk is not a toy. */
function payload(data: Record<string, unknown>): Array<Record<string, unknown>> {
  return [{ source: "dataset", tool: "get_cve", args: {}, rows: 1, data }];
}

describe("numbers: a percentage against the probability a payload stores", () => {
  const haystack = payload({ epss: { status: "known", value: "0.99999", percentile: "100" } });

  it("verifies the percentage the fraction means, and reports one it does not", () => {
    expect(unverifiedAnswerNumbers("EPSS is 99.999% for this record.", haystack)).toEqual([]);
    // 99.2% is 0.992: eight thousandths away from the payload, far outside the
    // one-unit tolerance a one-decimal printing earns.
    expect(unverifiedAnswerNumbers("EPSS is 99.2% for this record.", haystack)).toEqual(["99.2%"]);
  });

  it("verifies a percentage the payload printed as text", () => {
    expect(unverifiedAnswerNumbers("EPSS is 99.999%.", payload({ epssText: "99.999%" }))).toEqual(
      [],
    );
  });
});

describe("numbers: counts match exactly, separators stripped", () => {
  const haystack = payload({ total: 4110, returned: 25 });

  it("matches a thousands-separated count against the raw number", () => {
    expect(unverifiedAnswerNumbers("4,110 records match.", haystack)).toEqual([]);
    expect(unverifiedAnswerNumbers("4110 records match.", haystack)).toEqual([]);
  });

  it("reports a count one different", () => {
    expect(unverifiedAnswerNumbers("4,111 records match.", haystack)).toEqual(["4,111"]);
  });
});

describe("numbers: EPSS decimals and the tolerance of their own precision", () => {
  const haystack = payload({ epss: 0.99999 });

  it("verifies the exact value the payload held", () => {
    expect(unverifiedAnswerNumbers("An EPSS of 0.99999.", haystack)).toEqual([]);
  });

  it("verifies a value rounded to one fewer digit", () => {
    // `0.9999` is 9e-5 from the payload: inside one unit of its last digit.
    expect(unverifiedAnswerNumbers("An EPSS of 0.9999.", haystack)).toEqual([]);
  });

  it("reports a value two digits coarser than the payload can excuse", () => {
    expect(unverifiedAnswerNumbers("An EPSS of 0.998.", haystack)).toEqual(["0.998"]);
  });
});

describe("numbers: ISO dates are exact", () => {
  const haystack = payload({
    record: { publishedAt: "2026-11-22", dateUpdated: "2026-11-23T04:05:06.000Z" },
  });

  it("verifies a date the payload held, including one inside a timestamp", () => {
    expect(unverifiedAnswerNumbers("Published 2026-11-22.", haystack)).toEqual([]);
    expect(unverifiedAnswerNumbers("Updated 2026-11-23.", haystack)).toEqual([]);
  });

  it("reports a date one day off", () => {
    expect(unverifiedAnswerNumbers("Published 2026-11-21.", haystack)).toEqual(["2026-11-21"]);
  });
});

describe("numbers: what the pass refuses to check", () => {
  const haystack = payload({ items: [{ cveId: "CVE-2021-44228" }] });

  it("ignores list numbering, small counts and a bare year", () => {
    const prose =
      "1. First, add 2 records.\n2. Wait 30 days, or 45 at most, and ask again in 2026.\n" +
      "That is two records and a 10-point rise.";
    expect(extractAnswerNumbers(prose)).toEqual([]);
    expect(unverifiedAnswerNumbers(prose, haystack)).toEqual([]);
  });

  it("never reads a record id's digits as a number", () => {
    // `44228` and `2099` are inside ids, not figures; a pass that flagged them
    // would accuse every answer that names a record.
    expect(extractAnswerNumbers("CVE-2021-44228 and `CVE-2099-9999` both matter.")).toEqual([]);
    expect(extractAnswerNumbers("CWE-1321 describes it.")).toEqual([]);
  });

  it("reports nothing when the turn collected no payload", () => {
    // Nothing to compare against: a number is unchecked, never doubtful.
    expect(unverifiedAnswerNumbers("4,110 records and 99.2% of the corpus.", [])).toEqual([]);
  });

  it("reports nothing for a refusal, because nothing was read", async () => {
    const events: AssistantEvent[] = [];
    for await (const event of runRefusalTurn()) events.push(event);
    const done = events[events.length - 1];
    expect(done).toMatchObject({ type: "done", kind: "refusal" });
    for (const event of events) expect(event).not.toHaveProperty("unverifiedNumbers");
  });
});

describe("numbers: one list, in the order the answer printed them", () => {
  it("reports only the unsupported figures, deduplicated", () => {
    const haystack = payload({ total: 4110, record: { publishedAt: "2026-11-22" } });
    const prose =
      "4,110 records were published on 2026-11-22. " +
      "The rest is 99.2%, or 4,111 if you count 2026-11-23, and 4,110 again.";
    expect(unverifiedAnswerNumbers(prose, haystack)).toEqual(["99.2%", "4,111", "2026-11-23"]);
  });

  it("keeps the printed form rather than a normalised one", () => {
    expect(extractAnswerNumbers("4,110 and 4110 and 4,110").map((token) => token.text)).toEqual([
      "4,110",
    ]);
  });
});
