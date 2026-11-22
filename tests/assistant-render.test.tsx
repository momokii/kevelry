// The answer renderer, asserted against its markup.
//
// Two properties matter here and neither is cosmetic. First, model output is
// never markup: every XSS fixture below must come out as visible characters and
// as no element at all, and no anchor may exist for a scheme the link policy
// rejects. Second, the shaping must survive a stream: a table that has only
// arrived as a header row is text, not a half-built grid.
//
// The tests render the same way the page does — `renderToStaticMarkup` on the
// renderer's own output — and then parse that string, so the assertion is about
// the document a browser would build, not about a substring that happens to look
// right.
//
// @vitest-environment jsdom

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { renderAnswer, safeHref } from "../src/components/assistant/render-answer";
import { buildBriefMarkdown } from "../src/components/assistant/assistant-brief";

function markup(text: string, verifiedIds: readonly string[] = []): string {
  return renderToStaticMarkup(<>{renderAnswer(text, { verifiedIds })}</>);
}

function parse(html: string): Document {
  return new DOMParser().parseFromString(html, "text/html");
}

const TABLE = [
  "| Record | Score | Status |",
  "| --- | --- | --- |",
  "| CVE-2024-1234 | 9.8 | KEV |",
  "| CVE-2024-5678 | 7.5 | not listed |",
].join("\n");

describe("model output is text, never markup", () => {
  it("renders <script> as visible characters and creates no script element", () => {
    const html = markup("<script>alert(1)</script>");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    const doc = parse(html);
    expect(doc.querySelector("script")).toBeNull();
    expect(doc.body.textContent).toBe("<script>alert(1)</script>");
  });

  it("renders <img onerror> as visible characters and creates no img element", () => {
    const html = markup("<img src=x onerror=alert(1)>");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    const doc = parse(html);
    expect(doc.querySelector("img")).toBeNull();
    expect(doc.body.textContent).toBe("<img src=x onerror=alert(1)>");
  });

  it("renders markup inside a table cell as characters too", () => {
    const html = markup(
      ["| A | B |", "| --- | --- |", "| <script>alert(1)</script> | <b>x</b> |"].join("\n"),
    );
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<b>");
    const doc = parse(html);
    expect(doc.querySelectorAll("table td")).toHaveLength(2);
  });
});

describe("the link policy", () => {
  it.each([
    ["javascript: URL", "[x](javascript:alert(1))"],
    ["data: URL", "[x](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)"],
    ["vbscript: URL", "[x](vbscript:msgbox(1))"],
    ["protocol-relative URL", "[x](//evil.example/login)"],
    ["plain http URL", "[x](http://evil.example/)"],
    ["scheme-less relative path", "[x](explore?q=CVE-2024-1234)"],
    ["backslash host trick", "[x](/\\evil.example/)"],
  ])("refuses a %s and leaves the model's characters as text", (_name, fixture) => {
    const html = markup(fixture);
    expect(html).not.toContain("<a");
    expect(html).not.toContain("href=");
    const doc = parse(html);
    expect(doc.querySelector("a")).toBeNull();
    // Nothing is dropped: the reader sees exactly what the model proposed, and
    // sees that it is not a link.
    expect(doc.body.textContent).toBe(fixture);
  });

  it("resolves only https and same-origin paths", () => {
    expect(safeHref("https://example.org/advisory?x=1")).toBe("https://example.org/advisory?x=1");
    expect(safeHref("/explore?q=CVE-2024-1234")).toBe("/explore?q=CVE-2024-1234");
    expect(safeHref("/explore?q=CVE-2024-1234#cited")).toBe("/explore?q=CVE-2024-1234#cited");
    expect(safeHref("//evil.example/")).toBeNull();
    expect(safeHref("/\\evil.example/")).toBeNull();
    expect(safeHref("/../\\evil.example/")).toBeNull();
    expect(safeHref("javascript:alert(1)")).toBeNull();
    expect(safeHref("JavaScript:alert(1)")).toBeNull();
    expect(safeHref("data:text/html;base64,AA==")).toBeNull();
    expect(safeHref("http://example.org/")).toBeNull();
    expect(safeHref("https://user:pass@example.org/")).toBeNull();
    expect(safeHref("  ")).toBeNull();
  });

  it("links an allowed target, opening an external one without a referrer", () => {
    const html = markup(
      "See [the advisory](https://example.org/a/1) and [the record](/explore?q=CVE-2024-1234).",
    );
    const doc = parse(html);
    const links = Array.from(doc.querySelectorAll("a"));
    expect(links).toHaveLength(2);
    expect(links[0]?.getAttribute("href")).toBe("https://example.org/a/1");
    expect(links[0]?.getAttribute("rel")).toBe("noopener noreferrer");
    expect(links[0]?.getAttribute("target")).toBe("_blank");
    expect(links[1]?.getAttribute("href")).toBe("/explore?q=CVE-2024-1234");
    expect(links[1]?.getAttribute("rel")).toBeNull();
    expect(links[1]?.getAttribute("target")).toBeNull();
  });
});

describe("tables", () => {
  it("renders a 3-column pipe table with scoped headers and both body rows", () => {
    const doc = parse(markup(TABLE));
    const table = doc.querySelector("table");
    expect(table).not.toBeNull();
    expect(table?.className).toContain("data-table");

    const headers = Array.from(doc.querySelectorAll("thead th"));
    expect(headers).toHaveLength(3);
    expect(headers.map((cell) => cell.getAttribute("scope"))).toEqual(["col", "col", "col"]);
    expect(headers.map((cell) => cell.textContent)).toEqual(["Record", "Score", "Status"]);

    const rows = Array.from(doc.querySelectorAll("tbody tr"));
    expect(rows).toHaveLength(2);
    expect(rows[0]?.querySelectorAll("td")).toHaveLength(3);
    expect(rows[1]?.textContent).toBe("CVE-2024-56787.5not listed");
  });

  it("sets an id cell in the monospace id style", () => {
    const doc = parse(markup(TABLE));
    const first = doc.querySelector("tbody tr td");
    expect(first?.className).toBe("cell-id");
    expect(first?.textContent).toBe("CVE-2024-1234");
    // The measure cell is not an id and keeps the ordinary cell style.
    expect(doc.querySelectorAll("tbody tr td")[1]?.className).toBe("");
  });

  it("pads a short row to the header width instead of dropping the row", () => {
    const doc = parse(markup(["| A | B | C |", "| --- | --- | --- |", "| one | two |"].join("\n")));
    const cells = doc.querySelectorAll("tbody tr td");
    expect(cells).toHaveLength(3);
    expect(cells[2]?.textContent).toBe("");
  });

  it("wraps the table in the app's scroll container, focusable for a keyboard", () => {
    const columns = ["A", "B", "C", "D", "E", "F"];
    const doc = parse(
      markup(
        [
          `| ${columns.join(" | ")} |`,
          `| ${columns.map(() => "---").join(" | ")} |`,
          `| ${columns.map(() => "a long cell value").join(" | ")} |`,
        ].join("\n"),
      ),
    );
    const wrapper = doc.querySelector('[data-testid="assistant-table"]');
    expect(wrapper?.className).toBe("table-wrap");
    expect(wrapper?.getAttribute("tabindex")).toBe("0");
    expect(wrapper?.getAttribute("role")).toBe("region");
    expect(wrapper?.getAttribute("aria-label")).toBe("Answer table");
    expect(wrapper?.querySelector("table")).not.toBeNull();
  });

  it("renders a header row with no separator yet as text, not a half table", () => {
    // Exactly what the stream holds between the header delta and the separator
    // delta: a header line and one body line, no `| --- |`.
    const partial = "| Record | Score |\n| CVE-2024-1234 | 9.8 |";
    const html = markup(partial);
    expect(html).not.toContain("<table");
    expect(html).not.toContain("<th");
    const doc = parse(html);
    expect(doc.querySelector("table")).toBeNull();
    expect(doc.querySelector("p")?.textContent).toBe(
      "| Record | Score |" + "| CVE-2024-1234 | 9.8 |",
    );
    // The line break survives, so the header still reads as its own line.
    expect(doc.querySelectorAll("br")).toHaveLength(1);
  });

  it("keeps a table intact once the separator row arrives", () => {
    expect(markup("| Record | Score |\n| --- | --- |")).toContain("<table");
  });
});

describe("lists, emphasis and inline code", () => {
  it("renders unordered and ordered lists", () => {
    const doc = parse(markup("Intro\n\n- one\n- two\n\n1. first\n2. second"));
    const unordered = doc.querySelector("ul");
    const ordered = doc.querySelector("ol");
    expect(Array.from(unordered?.querySelectorAll("li") ?? []).map((li) => li.textContent)).toEqual(
      ["one", "two"],
    );
    expect(Array.from(ordered?.querySelectorAll("li") ?? []).map((li) => li.textContent)).toEqual([
      "first",
      "second",
    ]);
    expect(ordered?.hasAttribute("start")).toBe(false);
  });

  it("keeps the number an ordered list starts at", () => {
    const doc = parse(markup("3. third\n4. fourth"));
    expect(doc.querySelector("ol")?.getAttribute("start")).toBe("3");
  });

  it("renders bold, italic and inline code as elements around text", () => {
    const html = markup("**bold** and *italic* and `code`");
    expect(html).toContain("<strong>bold</strong>");
    expect(html).toContain("<em>italic</em>");
    expect(html).toContain("<code>code</code>");
    expect(parse(html).body.textContent).toBe("bold and italic and code");
  });

  it("does not italicise arithmetic", () => {
    const doc = parse(markup("2 * 3 * 4"));
    expect(doc.querySelector("em")).toBeNull();
    expect(doc.body.textContent).toBe("2 * 3 * 4");
  });

  it("keeps inline code verbatim, including its own asterisks", () => {
    const doc = parse(markup("use `a**b**c` here"));
    expect(doc.querySelector("code")?.textContent).toBe("a**b**c");
    expect(doc.querySelector("strong")).toBeNull();
  });
});

describe("record ids in prose", () => {
  it("links a cited id to the explore search, like a citation chip", () => {
    const doc = parse(markup("The record CVE-2024-1234 was added this week.", ["CVE-2024-1234"]));
    const links = Array.from(doc.querySelectorAll("a"));
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute("href")).toBe("/explore?q=CVE-2024-1234");
    expect(links[0]?.textContent).toBe("CVE-2024-1234");
    expect(doc.body.textContent).toBe("The record CVE-2024-1234 was added this week.");
  });

  it("leaves an id the server never cited as text", () => {
    // The grounding rule: an id no tool returned cannot gain a link that implies
    // the dataset holds it. The answer is unchanged; only the anchor is absent.
    const doc = parse(markup("See CVE-2099-9999, which is not in the data.", ["CVE-2099-0001"]));
    expect(doc.querySelector("a")).toBeNull();
    expect(doc.body.textContent).toBe("See CVE-2099-9999, which is not in the data.");
  });

  it("leaves every id as text when the turn cited nothing", () => {
    const doc = parse(markup("The record CVE-2024-1234 was added this week."));
    expect(doc.querySelector("a")).toBeNull();
  });

  it("does not link an id that is only part of a longer token", () => {
    const doc = parse(markup("XVECVE-2024-1234 is not an id.", ["CVE-2024-1234"]));
    expect(doc.querySelector("a")).toBeNull();
  });

  it("does not link an id an id that is already a link's label", () => {
    const doc = parse(markup("See [CVE-2024-1234](/explore?q=CVE-2024-1234).", ["CVE-2024-1234"]));
    const links = Array.from(doc.querySelectorAll("a"));
    expect(links).toHaveLength(1);
    expect(links[0]?.getAttribute("href")).toBe("/explore?q=CVE-2024-1234");
    expect(links[0]?.querySelector("a")).toBeNull();
    // No second anchor was minted inside the label.
    expect(doc.querySelectorAll("a a")).toHaveLength(0);
  });

  it("does not link an id inside inline code", () => {
    const doc = parse(markup("Ask for `CVE-2024-1234`.", ["CVE-2024-1234"]));
    expect(doc.querySelector("a")).toBeNull();
    expect(doc.querySelector("code")?.textContent).toBe("CVE-2024-1234");
  });
});

describe("briefs keep the raw answer", () => {
  it("emits the model's text unchanged, pipes and all", () => {
    const markdown = buildBriefMarkdown({
      turn: {
        id: "turn-1",
        question: "Which records count?",
        answer: `${TABLE}\n\n**Bold** stays raw.`,
        citations: [],
        unverified: [],
        tools: [],
      },
      modelId: "test-model",
      origin: "https://example.org",
      now: new Date("2026-11-22T00:00:00.000Z"),
    });
    expect(markdown).toContain("| Record | Score | Status |");
    expect(markdown).toContain("| --- | --- | --- |");
    expect(markdown).toContain("**Bold** stays raw.");
    // The brief is a Markdown file, not a rendered page: no anchors are minted.
    expect(markdown).not.toContain("/explore?q=CVE-2024-1234");
  });
});
