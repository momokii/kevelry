// Follow-ups are derived from the ledger, never written by the model.
//
// The property the tests protect: a chip cannot name an id the turn did not
// read. So every interpolation is checked back against the tool line that
// produced it, and a turn with no ledger produces no chips at all — even when
// its prose talks about KEV, EPSS or a CWE.

import { describe, expect, it } from "vitest";

import { buildFollowUps } from "../src/components/assistant/assistant-followups";
import type { AssistantToolLine } from "../src/components/assistant/assistant-state";

function line(overrides: Partial<AssistantToolLine> = {}): AssistantToolLine {
  return {
    id: "tool-1",
    name: "kev_window",
    args: "days=30",
    rows: 2,
    ok: true,
    ids: ["CVE-2099-0001", "CVE-2099-0002"],
    ...overrides,
  };
}

describe("follow-up derivation", () => {
  it("[CODE] offers a KEV deadline chip for a record the KEV window returned", () => {
    const chips = buildFollowUps({ tools: [line()] });
    expect(chips).toHaveLength(1);
    expect(chips[0]).toMatchObject({
      kind: "kev",
      subject: "CVE-2099-0001",
      question: "When is CVE-2099-0001 due?",
    });
  });

  it("[CODE] offers an EPSS trajectory chip from the history call's own id", () => {
    const chips = buildFollowUps({
      tools: [
        line({
          name: "epss_history",
          args: "id=CVE-2099-0002 · days=30",
          rows: 30,
          ids: ["CVE-2099-0002"],
        }),
      ],
    });
    expect(chips).toEqual([
      {
        id: "followup-epss-history",
        kind: "epss",
        subject: "CVE-2099-0002",
        question: "How has EPSS moved for CVE-2099-0002?",
      },
    ]);
  });

  it("[CODE] offers a CWE mitigation chip from the lookup argument", () => {
    const chips = buildFollowUps({
      tools: [line({ name: "cwe_lookup", args: "cweId=CWE-79", rows: 1, ids: [] })],
    });
    expect(chips).toEqual([
      {
        id: "followup-cwe-mitigation",
        kind: "cwe",
        subject: "CWE-79",
        question: "What does CWE-79 mitigate?",
      },
    ]);
  });

  it("[CODE] orders KEV, then EPSS, then CWE", () => {
    const chips = buildFollowUps({
      tools: [
        line({ id: "t1", name: "kev_window" }),
        line({ id: "t2", name: "epss_history", args: "id=CVE-2099-0002", ids: [] }),
        line({ id: "t3", name: "cwe_lookup", args: "cweId=CWE-89", ids: [] }),
      ],
    });
    expect(chips.map((chip) => chip.kind)).toEqual(["kev", "epss", "cwe"]);
  });

  it("[CODE] offers nothing when the ledger is empty", () => {
    expect(buildFollowUps({ tools: [] })).toEqual([]);
  });

  it("[CODE] offers nothing for a failed call or an empty result set", () => {
    expect(buildFollowUps({ tools: [line({ ok: false })] })).toEqual([]);
    expect(buildFollowUps({ tools: [line({ ids: [], rows: 0 })] })).toEqual([]);
    expect(
      buildFollowUps({
        tools: [line({ name: "epss_history", args: "id=CVE-2099-0002", ok: false })],
      }),
    ).toEqual([]);
  });

  it("[CODE] never interpolates an id the turn did not read", () => {
    const tools = [
      line({ id: "t1", name: "kev_window" }),
      line({ id: "t2", name: "epss_history", args: "id=CVE-2099-0002", ids: [] }),
      line({ id: "t3", name: "cwe_lookup", args: "cweId=CWE-79", ids: [] }),
    ];
    const ledgerText = tools.map((tool) => `${tool.args} ${tool.ids.join(" ")}`).join(" ");
    for (const chip of buildFollowUps({ tools })) {
      expect(ledgerText).toContain(chip.subject);
      expect(chip.question).toContain(chip.subject);
    }
  });

  it("[CODE] does not repeat the same record as both a KEV and an EPSS chip", () => {
    const chips = buildFollowUps({
      tools: [
        line({ id: "t1", name: "kev_window", ids: ["CVE-2099-0001"] }),
        line({ id: "t2", name: "epss_history", args: "id=CVE-2099-0001", ids: [] }),
      ],
    });
    expect(chips.map((chip) => chip.kind)).toEqual(["kev"]);
  });
});
