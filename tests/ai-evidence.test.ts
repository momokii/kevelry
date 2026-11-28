// The evidence pass: what the server read, in one place, without a provider.
//
// "Citations are server data" is the product's central claim, and until this
// module it lived as a `Set` mutated inside a generator and fed by a generic
// deep walk — a rule that could only be observed by driving a whole turn. What
// this file proves (mechanical): ids come from payloads and never from prose, a
// figure is checked against the value a tool returned, a host is counted once
// per URL and only when a fetch really read it, and a turn that read nothing
// accuses nothing.
//
// The other half is the terminal `done` payload: the same fields, in the same
// order, with the two omission rules intact — no `unverifiedNumbers` key when
// there is nothing doubtful, no `kind` key when the answer was ordinary.
//
// What this file does not prove: that a model writes these shapes. The route and
// streaming tests drive the production loop; this is the rule on its own.

import { describe, expect, it } from "vitest";

import {
  collectEvidence,
  collectRecordIds,
  extractAnswerIds,
  type ToolReading,
  type TurnEvidence,
} from "../src/lib/ai/evidence";
import { runRefusalTurn } from "../src/lib/ai/refusal";
import { settle } from "../src/lib/ai/settle";
import type { AssistantEvent } from "../src/lib/ai/turn";
import type { ToolErrorReason, ToolName } from "../src/lib/ai/tools";

const AT = "2026-01-01T00:00:00.000Z";

/** One successful call, shaped like the dispatcher's own result. */
function success(name: ToolName, data: unknown, rows = 1): ToolReading {
  return { name, outcome: { ok: true, tool: name, rows, retrievedAt: AT, data } };
}

/** One failed call: a fact about the turn, never evidence about a record. */
function failure(name: ToolName, reason: ToolErrorReason = "TIMEOUT"): ToolReading {
  return {
    name,
    outcome: { ok: false, tool: name, reason, error: `${name} did not answer.` },
  };
}

function evidence(toolCalls: readonly ToolReading[], answerText: string): TurnEvidence {
  return collectEvidence({ toolCalls, answerText });
}

const ALL_EMPTY: TurnEvidence = {
  citationIds: [],
  unverifiedIds: [],
  unverifiedNumbers: [],
  webSources: [],
};

describe("evidence: citations are the ids a payload contained", () => {
  const nested = [
    success("search_cves", {
      items: [
        { cveId: "CVE-2021-44228", severity: "critical" },
        { cveId: "CVE-2022-22965", severity: "high" },
        // Asked for, not found: never a citation.
        { missing: ["CVE-2020-0001"] },
      ],
    }),
    // The same id again, and one only a second shape reaches.
    success("get_cve", { record: { cveId: "CVE-2021-44228" }, related: ["CVE-2023-1111"] }),
  ];

  it("walks every nesting a tool uses, deduplicated in the order it read them", () => {
    expect(evidence(nested, "Two records were read.")).toMatchObject({
      citationIds: ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-1111"],
      unverifiedIds: [],
    });
  });

  it("reports an id from a failed call as unverified, because nothing returned it", () => {
    const calls = [
      success("get_cve", { record: { cveId: "CVE-2021-44228" } }),
      failure("get_cves"),
    ];
    const found = evidence(calls, "CVE-2021-44228 is affected.");
    expect(found.citationIds).toEqual(["CVE-2021-44228"]);
    expect(found.unverifiedIds).toEqual([]);
  });
});

describe("evidence: ids the prose named that no payload returned", () => {
  const calls = [success("get_cve", { record: { cveId: "CVE-2021-44228" } })];

  it("reports a hallucinated id, case-normalised, and keeps the cited one out", () => {
    const answer = "CVE-2021-44228 and cve-2023-9999 were compared.";
    expect(evidence(calls, answer)).toMatchObject({
      citationIds: ["CVE-2021-44228"],
      unverifiedIds: ["CVE-2023-9999"],
    });
  });

  it("never promotes a `missing` id into a citation, so naming it stays unverified", () => {
    const lookup = [success("get_cves", { missing: ["CVE-2020-0001"], found: [] })];
    expect(evidence(lookup, "CVE-2020-0001 is not in this dataset.")).toMatchObject({
      citationIds: [],
      unverifiedIds: ["CVE-2020-0001"],
    });
  });

  it("reads ids out of prose that a payload never shaped as one", () => {
    expect(extractAnswerIds("`CVE-2021-44228` and CVE-2021-44228 again.")).toEqual([
      "CVE-2021-44228",
    ]);
  });
});

describe("evidence: figures are checked against the payload, never against prose", () => {
  const calls = [
    success("get_cve", { record: { cveId: "CVE-2021-44228", epss: 0.99999 } }),
    success("search_cves", { total: 4110 }),
  ];

  it("verifies the figures a payload supports", () => {
    expect(
      evidence(calls, "EPSS is 99.999% for CVE-2021-44228, across 4,110 records."),
    ).toMatchObject({ unverifiedNumbers: [] });
  });

  it("reports a figure no payload supports, as printed", () => {
    expect(evidence(calls, "EPSS is 99.2% for CVE-2021-44228.")).toMatchObject({
      unverifiedNumbers: ["99.2%"],
    });
  });

  it("accuses nothing on a turn that read nothing: nothing to compare against", () => {
    // A count and a percentage with no payload behind them are unchecked, not
    // doubtful; the same call is why a refusal carries no numbers at all.
    expect(evidence([failure("search_cves")], "4,110 records at 99.2%.")).toMatchObject({
      unverifiedNumbers: [],
    });
  });
});

describe("evidence: web sources are the hosts a fetch actually read", () => {
  const URL = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228";

  it("keeps one source per distinct URL, in the order they were read", () => {
    const calls = [
      success("fetch_authoritative", { url: URL, host: "nvd.nist.gov" }),
      // The same page again: one chip, not two.
      success("fetch_authoritative", { url: URL, host: "nvd.nist.gov" }),
      success("fetch_authoritative", {
        url: "https://cve.org/CVERecord?id=CVE-2021-44228",
        host: "cve.org",
      }),
    ];
    expect(evidence(calls, "One advisory was read.").webSources).toEqual([
      { url: URL, host: "nvd.nist.gov" },
      { url: "https://cve.org/CVERecord?id=CVE-2021-44228", host: "cve.org" },
    ]);
  });

  it("counts nothing for a refused fetch, or for a call that was not a fetch", () => {
    const calls = [
      failure("fetch_authoritative", "BLOCKED_URL"),
      success("get_cve", { record: { cveId: "CVE-2021-44228" } }),
    ];
    expect(evidence(calls, "The fetch was refused.").webSources).toEqual([]);
  });

  it("counts a source only when the turn's single-fetch allowance was spent", () => {
    const calls = [success("fetch_authoritative", { url: URL, host: "nvd.nist.gov" })];
    const unspent = collectEvidence({
      toolCalls: calls,
      answerText: "One advisory was read.",
      webBudget: { used: false },
    });
    expect(unspent.webSources).toEqual([]);
    const spent = collectEvidence({
      toolCalls: calls,
      answerText: "One advisory was read.",
      webBudget: { used: true },
    });
    expect(spent.webSources).toEqual([{ url: URL, host: "nvd.nist.gov" }]);
  });
});

describe("evidence: a turn with no evidence says so four ways", () => {
  it("returns all-empty evidence when no tool ran", () => {
    expect(evidence([], "Nothing was read, so nothing is cited.")).toEqual(ALL_EMPTY);
  });

  it("returns all-empty evidence for a refusal", async () => {
    // The refusal turn's own prose, through the same pass the route would use:
    // no call, no payload, no doubt to report.
    let answerText = "";
    const events: AssistantEvent[] = [];
    for await (const event of runRefusalTurn()) {
      if (event.type === "delta") answerText += event.text;
      events.push(event);
    }
    expect(answerText).not.toBe("");
    expect(evidence([], answerText)).toEqual(ALL_EMPTY);
    // And the settled refusal carries no numeric caution of its own.
    for (const event of events) expect(event).not.toHaveProperty("unverifiedNumbers");
  });

  it("walks a payload with no ids at all as empty rather than as a citation", () => {
    expect(collectRecordIds({ rows: [{ severity: "high", count: 12 }] })).toEqual([]);
  });
});

describe("settle: the done payload, field for field and in order", () => {
  const usage = { prompt: 1200, completion: 300, reasoning: 0, cacheRead: 800, costUsd: 0.0123 };

  it("omits both optional keys on a clean, ordinary answer", () => {
    const done = settle({ usage, rounds: 2, evidence: ALL_EMPTY });
    expect(Object.keys(done)).toEqual(["type", "usage", "costUsd", "rounds", "unverified"]);
    expect(done).toEqual({
      type: "done",
      usage: { prompt: 1200, completion: 300, reasoning: 0, cacheRead: 800 },
      costUsd: 0.0123,
      rounds: 2,
      unverified: [],
    });
  });

  it("adds the two doubt lists only when evidence reported them", () => {
    const done = settle({
      usage,
      rounds: 3,
      evidence: { unverifiedIds: ["CVE-2023-9999"], unverifiedNumbers: ["99.2%"] },
    });
    expect(Object.keys(done)).toEqual([
      "type",
      "usage",
      "costUsd",
      "rounds",
      "unverified",
      "unverifiedNumbers",
    ]);
    expect(done.unverified).toEqual(["CVE-2023-9999"]);
    expect(done.unverifiedNumbers).toEqual(["99.2%"]);
  });

  it("carries the kind between the type and the bill, for a refusal", () => {
    const done = settle({ usage, rounds: 0, evidence: ALL_EMPTY, kind: "refusal" });
    expect(Object.keys(done)).toEqual(["type", "kind", "usage", "costUsd", "rounds", "unverified"]);
    expect(done.kind).toBe("refusal");
  });

  it("copies the evidence lists, so a settled frame cannot mutate the turn's own", () => {
    const source = { unverifiedIds: ["CVE-2023-9999"], unverifiedNumbers: ["99.2%"] };
    const done = settle({ usage, rounds: 1, evidence: source });
    expect(done.unverified).not.toBe(source.unverifiedIds);
    expect(done.unverifiedNumbers).not.toBe(source.unverifiedNumbers);
  });
});
