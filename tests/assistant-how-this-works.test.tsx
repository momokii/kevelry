// "How this works": the page's contract, in three sentences and one flag.
//
// The unit under test is the page's disclosure, not the desk. Its rule is that
// the reader is told the same contract the code enforces — grounded answers,
// numbers from the records beside them, nothing stored — and that the web
// fallback is mentioned only when this deployment can actually fetch. Both
// branches are asserted, because a conditional clause is a promise either way.
//
// @vitest-environment jsdom

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AssistantHowThisWorks } from "../src/components/assistant/AssistantHowThisWorks";

function render(webEnabled: boolean): string {
  return renderToStaticMarkup(<AssistantHowThisWorks webEnabled={webEnabled} />);
}

const SENTENCES = [
  "Answers come from tool calls over this deployment",
  "Numbers come from the records listed beside the answer",
  "Nothing you type is stored",
];

const WEB_CLAUSE =
  "When the dataset cannot answer, it may read an allow-listed page and cite the URL.";

describe("How this works", () => {
  it("is a closed disclosure labelled in the reader's words", () => {
    const html = render(false);
    expect(html).toContain('data-testid="assistant-how"');
    expect(html).toContain('class="assistant-how-summary">How this works</summary>');
    // Closed by default: the mechanics are available, never in the way.
    expect(html).not.toContain(" open");
  });

  it("states the three sentences the desk actually keeps", () => {
    const html = render(false);
    for (const sentence of SENTENCES) {
      expect(html, sentence).toContain(sentence);
    }
  });

  it("mentions no web fallback when the deployment cannot fetch", () => {
    const html = render(false);
    expect(html).not.toContain(WEB_CLAUSE);
    expect(html).not.toContain('data-testid="assistant-how-web"');
    // Three sentences, not three and a dangling clause.
    expect(html).not.toContain("allow-listed page");
  });

  it("adds the fallback clause only when the flag is on", () => {
    const html = render(true);
    expect(html).toContain(WEB_CLAUSE);
    expect(html).toContain('data-testid="assistant-how-web"');
    // The three base sentences are unchanged by the fourth.
    for (const sentence of SENTENCES) {
      expect(html, sentence).toContain(sentence);
    }
  });
});
