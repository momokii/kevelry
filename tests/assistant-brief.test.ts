// The brief: a downloaded answer has to carry its own provenance.
//
// Two claims matter and both are text properties: every citation is an absolute
// link, and the footer states that the prose is model-written while the figures
// come from the dataset. The table is Markdown, so a pipe or a newline inside an
// argument is escaped rather than allowed to break the document.

import { describe, expect, it } from "vitest";

import {
  BRIEF_DISCLAIMER,
  BRIEF_UNVERIFIED_NOTE,
  BRIEF_UNVERIFIED_NUMBERS_NOTE,
  briefFileName,
  buildBriefMarkdown,
  type BriefInput,
} from "../src/components/assistant/assistant-brief";

function input(overrides: Partial<BriefInput> = {}): BriefInput {
  return {
    modelId: "deepseek-v4.1-flash",
    origin: "https://kevelry.test",
    now: new Date("2026-11-22T10:00:00.000Z"),
    turn: {
      id: "turn-1",
      question: "Which KEV entries were added in the last 30 days?",
      answer: "Forty-one records entered the catalog. CVE-2026-41077 is one of them.",
      citations: ["CVE-2026-41077", "CVE-2026-41820"],
      unverified: [],
      unverifiedNumbers: [],
      tools: [
        {
          id: "tool-1",
          name: "kev_window",
          args: "days=30",
          rows: 41,
          ok: true,
          ids: ["CVE-2026-41077"],
        },
      ],
    },
    ...overrides,
  };
}

describe("brief Markdown", () => {
  it("[CODE] opens with the question and carries the answer verbatim", () => {
    const markdown = buildBriefMarkdown(input());
    expect(markdown.startsWith("# Which KEV entries were added in the last 30 days?")).toBe(true);
    expect(markdown).toContain("Forty-one records entered the catalog.");
  });

  it("[CODE] prints every citation as an absolute /explore link", () => {
    const markdown = buildBriefMarkdown(input());
    expect(markdown).toContain("- [CVE-2026-41077](https://kevelry.test/explore?q=CVE-2026-41077)");
    expect(markdown).toContain("- [CVE-2026-41820](https://kevelry.test/explore?q=CVE-2026-41820)");
    const links = markdown.match(/\]\(([^)]+)\)/g) ?? [];
    for (const link of links) expect(link).toMatch(/\]\(https:\/\//);
  });

  it("[CODE] lists every tool call with its name, arguments and row count", () => {
    const markdown = buildBriefMarkdown(input());
    expect(markdown).toContain("## Evidence");
    expect(markdown).toContain("| Tool | Arguments | Rows |");
    expect(markdown).toContain("| kev_window | days=30 | 41 |");
  });

  it("[CODE] escapes pipes and newlines inside a table cell", () => {
    const markdown = buildBriefMarkdown(
      input({
        turn: {
          ...input().turn,
          tools: [
            {
              id: "tool-1",
              name: "get_cve",
              args: "id=CVE-2026-41077 · note=a|b\nc",
              rows: 1,
              ok: true,
              ids: [],
            },
          ],
        },
      }),
    );
    expect(markdown).toContain("| get_cve | id=CVE-2026-41077 · note=a\\|b c | 1 |");
    // The row is still one line: the newline became a space, not a second row.
    const rows = markdown.split("\n").filter((line) => line.startsWith("| get_cve"));
    expect(rows).toHaveLength(1);
  });

  it("[CODE] says so when nothing was cited or no call was recorded", () => {
    const markdown = buildBriefMarkdown(
      input({
        turn: { ...input().turn, citations: [], tools: [], answer: "No record matched." },
      }),
    );
    expect(markdown).toContain("No record was cited in this answer.");
    expect(markdown).toContain("No tool call was recorded for this answer.");
  });

  it("[CODE] prints the model id and the model-written/dataset disclaimer", () => {
    const markdown = buildBriefMarkdown(input());
    expect(markdown).toContain("model `deepseek-v4.1-flash`");
    expect(markdown).toContain(BRIEF_DISCLAIMER);
    expect(markdown).toContain("The prose above is model-written");
    expect(markdown).toContain("Every figure comes from the dataset");
  });

  it("[CODE] includes an Unverified ids section only when the list is non-empty", () => {
    const clean = buildBriefMarkdown(input());
    expect(clean).not.toContain("## Unverified ids");
    expect(clean).not.toContain(BRIEF_UNVERIFIED_NOTE);

    const flagged = buildBriefMarkdown(
      input({ turn: { ...input().turn, unverified: ["CVE-2099-9999"] } }),
    );
    expect(flagged).toContain("## Unverified ids");
    expect(flagged).toContain("- `CVE-2099-9999`");
    // Not a link: the brief must not dress an unsupported id as a citation.
    expect(flagged).not.toContain("[CVE-2099-9999](");
    expect(flagged).toContain(BRIEF_UNVERIFIED_NOTE);
    // The footer's main claim is still there and still true of the evidence.
    expect(flagged).toContain(BRIEF_DISCLAIMER);
  });

  it("[CODE] includes an Unverified numbers section only when a figure was flagged", () => {
    const clean = buildBriefMarkdown(input());
    expect(clean).not.toContain("## Unverified numbers");
    expect(clean).not.toContain(BRIEF_UNVERIFIED_NUMBERS_NOTE);

    const flagged = buildBriefMarkdown(
      input({ turn: { ...input().turn, unverifiedNumbers: ["99.2%", "4,111"] } }),
    );
    expect(flagged).toContain("## Unverified numbers");
    expect(flagged).toContain(
      "The answer printed 2 numbers that no tool result this turn contained.",
    );
    // As printed in the answer, one per line, so the prose can be searched for
    // each one. Not links: a figure has no record to open.
    expect(flagged).toContain("- `99.2%`");
    expect(flagged).toContain("- `4,111`");
    expect(flagged).toContain(BRIEF_UNVERIFIED_NUMBERS_NOTE);
    // The disclaimer is still printed, and the section is what qualifies it.
    expect(flagged).toContain(BRIEF_DISCLAIMER);
    expect(flagged.indexOf("## Unverified numbers")).toBeLessThan(flagged.indexOf("## Evidence"));
  });

  it("[CODE] dates the file name and keeps it a .md", () => {
    expect(briefFileName(new Date("2026-11-22T23:59:59.000Z"))).toBe("kevelry-brief-2026-11-22.md");
  });
});
