// All six states of the desk, rendered from a typed failure.
//
// The requirement the desk has to meet is not "an error is shown" but "each
// state says what happened and what to do next, and the disabled states do not
// pretend to take a question". That is a property of the markup, so it is
// asserted against the markup: static rendering here, a live browser in
// `tests/e2e/assistant.spec.ts`.
//
// @vitest-environment jsdom

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AssistantView, type AssistantViewProps } from "../src/components/assistant/AssistantView";
import {
  budgetFault,
  disabledFault,
  faultFromCode,
  rateLimitedFault,
  type AssistantTurn,
} from "../src/components/assistant/assistant-state";
import type { AssistantSuggestion } from "../src/lib/ai/suggestions";

const SUGGESTIONS: AssistantSuggestion[] = [
  {
    id: "kev-additions",
    question: "Which KEV entries were added in the last 30 days?",
    count: 4,
    countLabel: "KEV additions",
  },
  {
    id: "kev-due",
    question: "Which KEV entries are due in the next 30 days?",
    count: 12045,
    countLabel: "catalog due dates",
  },
];

function turn(overrides: Partial<AssistantTurn> = {}): AssistantTurn {
  return {
    id: "turn-1",
    question: "Which KEV entries were added in the last 30 days?",
    answer: "Four records entered the catalog in the last 30 days.",
    settled: true,
    stopped: false,
    citations: ["CVE-2099-0001", "CVE-2099-0002"],
    unverified: [],
    tools: [
      {
        id: "tool-1",
        name: "kev_window",
        args: "days=30",
        rows: 4,
        ok: true,
        ids: ["CVE-2099-0001", "CVE-2099-0002"],
      },
    ],
    aboutCve: null,
    ...overrides,
  };
}

function baseProps(overrides: Partial<AssistantViewProps> = {}): AssistantViewProps {
  return {
    gate: { enabled: true },
    suggestions: SUGGESTIONS,
    turns: [],
    fault: null,
    status: "idle",
    activity: null,
    draft: "",
    aboutCve: null,
    image: null,
    imageFault: null,
    remainingSeconds: null,
    ledgerOpen: true,
    onDraftChange: () => undefined,
    onImagePick: () => undefined,
    onImageRemove: () => undefined,
    onCompare: () => undefined,
    onFollowUp: () => undefined,
    onBrief: () => undefined,
    onSubmit: () => undefined,
    onStop: () => undefined,
    onRetry: () => undefined,
    onSuggestion: () => undefined,
    onClearContext: () => undefined,
    onLedgerToggle: () => undefined,
    ...overrides,
  };
}

function render(overrides: Partial<AssistantViewProps> = {}): string {
  return renderToStaticMarkup(<AssistantView {...baseProps(overrides)} />);
}

describe("state 1 — empty", () => {
  it("offers each suggestion with its real count and a composer", () => {
    const html = render();
    expect(html).toContain("Which KEV entries were added in the last 30 days?");
    expect(html).toContain("4 KEV additions");
    // A grouped count, never a bare number, and never a fabricated placeholder.
    expect(html).toContain("12,045 catalog due dates");
    expect(html).toContain('data-testid="assistant-composer"');
    expect(html).toContain('id="assistant-question"');
  });

  it("says so when the corpus has nothing to suggest", () => {
    const html = render({ suggestions: [] });
    expect(html).toContain('data-testid="assistant-suggestions-empty"');
    expect(html).toContain("nothing to suggest");
    // The composer is still there: the corpus itself is always answerable.
    expect(html).toContain('data-testid="assistant-composer"');
  });

  it("states the privacy note and the key contract next to the composer", () => {
    const html = render();
    expect(html).toContain("a reload starts clean");
    expect(html).toContain("Enter sends");
    // The counter is a near-limit warning, not a permanent rubric.
    expect(html).not.toContain('data-testid="assistant-counter"');
  });

  it("shows the counter once the draft is near the limit", () => {
    const html = render({ draft: "x".repeat(1900) });
    expect(html).toContain('data-testid="assistant-counter"');
    expect(html).toContain("1900 / 2000");
  });
});

describe("state 2 — streaming", () => {
  it("names the tool activity, keeps the text, and offers Stop instead of Send", () => {
    const html = render({
      turns: [turn({ settled: false, answer: "Four records " })],
      status: "streaming",
      activity: "checking the KEV window · 4 records…",
    });
    expect(html).toContain('role="status"');
    expect(html).toContain("checking the KEV window · 4 records…");
    expect(html).toContain("Four records ");
    expect(html).toContain('data-testid="assistant-stop"');
    expect(html).not.toContain('data-testid="assistant-send"');
    // The composer is read-only, not disabled: focus stays where the reader left it.
    expect(html).toContain('aria-readonly="true"');
  });

  it("shows the 2px progress rule only before any text arrives", () => {
    const withRule = render({
      turns: [turn({ settled: false, answer: "", citations: [] })],
      status: "streaming",
      activity: "reading the record · 1 record…",
    });
    expect(withRule).toContain('data-testid="assistant-progress"');
    const withText = render({
      turns: [turn({ settled: false, answer: "Four" })],
      status: "streaming",
    });
    expect(withText).not.toContain('data-testid="assistant-progress"');
  });

  it("keeps the streaming answer out of the live region and the settled one in it", () => {
    const streaming = render({
      turns: [turn({ settled: false })],
      status: "streaming",
    });
    expect(streaming).toContain('aria-live="off"');
    const settled = render({ turns: [turn()] });
    expect(settled).toContain('aria-live="polite"');
  });

  it("marks a stopped turn as stopped and keeps what arrived", () => {
    const html = render({ turns: [turn({ stopped: true, answer: "Four records " })] });
    expect(html).toContain('data-testid="assistant-stopped"');
    expect(html).toContain("Stopped before the answer finished.");
    expect(html).toContain("Four records ");
  });
});

describe("state 3 — typed errors", () => {
  it("renders each provider failure with its sentence, its next step and its code", () => {
    const cases = [
      ["AI_TIMEOUT", "The model took too long; the question was not answered."],
      ["AI_UPSTREAM_ERROR", "The provider failed before the answer finished."],
      ["AI_TRUNCATED", "The answer was cut off; ask a narrower question."],
    ] as const;
    for (const [code, headline] of cases) {
      const html = render({ fault: faultFromCode(code) });
      expect(html, code).toContain('role="alert"');
      expect(html, code).toContain(headline);
      expect(html, code).toContain(code);
      expect(html, code).toContain('data-testid="assistant-send"');
    }
  });

  it("offers a retry only when asking again can work", () => {
    expect(render({ fault: faultFromCode("AI_TIMEOUT") })).toContain("Ask again");
    // A refusal needs a different question, not the same one again.
    expect(render({ fault: faultFromCode("AI_REFUSED") })).not.toContain("Ask again");
  });
});

describe("state 4 — rate limited", () => {
  it("renders the countdown and disables the composer until it expires", () => {
    const html = render({ fault: rateLimitedFault(43), remainingSeconds: 43 });
    expect(html).toContain("The assistant is rate limited on this connection.");
    expect(html).toContain("retry in 43 s");
    expect(html).toContain("RATE_LIMITED");
    // Disabled, not read-only: no question can be typed into a locked window.
    expect(html).toContain("disabled");
    expect(html).not.toContain('data-testid="assistant-stop"');
  });
});

describe("state 5 — budget exhausted", () => {
  it("explains the daily cap with its reset instant and the operator's variable", () => {
    const html = render({
      fault: budgetFault({ reason: "daily", resetAt: "2026-11-23T00:00:00.000Z" }),
      remainingSeconds: 5 * 3600 + 41 * 60,
    });
    expect(html).toContain("The assistant has spent today");
    expect(html).toContain("AI budget.");
    expect(html).toContain("reset");
    expect(html).toContain("00:00 UTC");
    expect(html).toContain("AI_DAILY_BUDGET_USD");
    expect(html).toContain("5 h 41 m");
  });

  it("states the session cap as a transcript limit, not as money", () => {
    const html = render({ fault: budgetFault({ reason: "session", resetAt: null }) });
    expect(html).toContain("This transcript has reached its token budget.");
    expect(html).toContain("AI_SESSION_BUDGET_TOKENS");
    // The panel's own line promises no reset for a session cap. The midnight
    // fact lives in the budget tip's explanation, which is supplementary and
    // names which cap ran out, so it is read from the meta line without it.
    const host = document.createElement("div");
    host.innerHTML = html;
    const meta = host.querySelector(".assistant-fault-meta");
    meta?.querySelector(".ledger-helptip")?.remove();
    expect(meta?.textContent).not.toContain("00:00 UTC");
  });
});

describe("state 6 — feature disabled", () => {
  it("renders the reason and the variable, and no composer at all", () => {
    for (const [reason, variable] of [
      ["off", "AI_ENABLED"],
      ["no-key", "AI_API_KEY"],
      ["over-budget", "AI_DAILY_BUDGET_USD"],
    ] as const) {
      const html = render({ gate: { enabled: false, reason } });
      expect(html, reason).toContain('data-testid="assistant-disabled"');
      expect(html, reason).toContain(variable);
      expect(html, reason).toContain(reason);
      // No fake chat UI: no field, no send button, no suggestion to click.
      expect(html, reason).not.toContain("<textarea");
      expect(html, reason).not.toContain('data-testid="assistant-send"');
      expect(html, reason).not.toContain('data-testid="assistant-suggestion-kev-additions"');
    }
  });

  it("uses the same copy a mid-session disable event produces", () => {
    const gateOff = render({
      gate: { enabled: false, reason: disabledFault("off").disabledReason ?? "off" },
    });
    expect(gateOff).toContain(disabledFault("off").headline);
  });
});

describe("unverified ids", () => {
  it("renders one quiet caution above the chips, naming the count and the id", () => {
    const html = render({ turns: [turn({ unverified: ["CVE-2099-9999"] })] });
    expect(html).toContain('data-testid="assistant-unverified"');
    expect(html).toContain('data-count="1"');
    expect(html).toContain(
      "1 record id in this answer was not found in the dataset: CVE-2099-9999.",
    );
    expect(html).toContain("It may be a typo or a record this deployment does not hold.");
    // Above the citations: the doubt is read before the evidence it qualifies.
    expect(html.indexOf('data-testid="assistant-unverified"')).toBeLessThan(
      html.indexOf('class="assistant-citations"'),
    );
  });

  it("counts in the plural and still spells the ids out", () => {
    const html = render({
      turns: [turn({ unverified: ["CVE-2099-9999", "CVE-2099-8888"] })],
    });
    expect(html).toContain('data-count="2"');
    expect(html).toContain("2 record ids in this answer were not found in the dataset");
    expect(html).toContain("CVE-2099-9999, CVE-2099-8888");
    expect(html).toContain("They may be typos or records this deployment does not hold.");
  });

  it("renders nothing when the server reported no unverified id", () => {
    const html = render({ turns: [turn()] });
    expect(html).not.toContain('data-testid="assistant-unverified"');
    // The supported citations are untouched by the absence of the caution.
    expect(html).toContain('data-testid="assistant-citation"');
  });
});

describe("the ledger and the citations", () => {
  it("lists one entry per tool call with its arguments, row count and record chips", () => {
    const html = render({ turns: [turn()] });
    expect(html).toContain("kev_window");
    expect(html).toContain("days=30");
    expect(html).toContain("4 rows");
    expect(html).toContain('href="/explore?q=CVE-2099-0001"');
    expect(html).toContain("1 tool call");
  });

  it("chips only the ids the server's citations event named", () => {
    const html = render({
      turns: [
        turn({
          answer: "See CVE-2099-9999, which is not in the data.",
          citations: ["CVE-2099-0001"],
        }),
      ],
    });
    expect(html).toContain('href="/explore?q=CVE-2099-0001"');
    // Prose never becomes a citation.
    expect(html).not.toContain('href="/explore?q=CVE-2099-9999"');
  });

  it("says an empty ledger is empty rather than showing a blank column", () => {
    const html = render();
    expect(html).toContain('data-testid="assistant-ledger-empty"');
    expect(html).toContain("no tool calls yet");
  });

  it("is a real disclosure with a label, so a narrow layout can fold it", () => {
    const html = render({ turns: [turn()] });
    expect(html).toContain("<details");
    expect(html).toContain('aria-label="Provenance ledger"');
    expect(html).toContain("<summary");
    // The visible title is stated once per layout: the heading wide, the summary narrow.
    expect(html).toContain('class="assistant-ledger-heading"');
    expect(html).toContain("Evidence");
  });

  it("pins the cve context as a removable chip above the composer", () => {
    const html = render({ aboutCve: "CVE-2021-44228" });
    expect(html).toContain('data-testid="assistant-context"');
    expect(html).toContain("about");
    expect(html).toContain("Stop scoping questions to CVE-2021-44228");
    expect(html).toContain('href="/explore?q=CVE-2021-44228"');
  });

  it("marks the question as scoped to the pinned record", () => {
    const html = render({ turns: [turn({ aboutCve: "CVE-2021-44228" })] });
    expect(html).toContain("You asked about CVE-2021-44228");
  });
});

describe("screenshot intake", () => {
  it("labels the file input and says what an image may and may not be used for", () => {
    const html = render();
    expect(html).toContain('type="file"');
    expect(html).toContain('accept="image/png,image/jpeg,image/webp"');
    // The label wraps the input, so the visible 44px target is the control's
    // own accessible name and the audit's target-size rule sees one box.
    expect(html).toContain('<label class="assistant-image-pick"><input id="assistant-image-input"');
    expect(html).toContain("Attach a screenshot");
    expect(html).toContain("The image is only used to find CVE ids");
    expect(html).toContain("every id is checked against the dataset before it is used");
  });

  it("shows a thumbnail, its name and size, and a Remove that names the file", () => {
    const html = render({
      image: {
        dataUrl: "data:image/png;base64,iVBORw0KGgo=",
        name: "shot.png",
        size: 62_000,
        mime: "image/png",
      },
    });
    expect(html).toContain('data-testid="assistant-image-preview"');
    expect(html).toContain('src="data:image/png;base64,iVBORw0KGgo="');
    expect(html).toContain('aria-label="Remove shot.png"');
    expect(html).toContain("61 KB");
    expect(html).toContain("PNG");
  });

  it("states a refusal in the reader's words, as an alert", () => {
    const html = render({ imageFault: "That image is 2.0 MB. The limit is 1.5 MB." });
    expect(html).toContain('role="alert"');
    expect(html).toContain('data-testid="assistant-image-fault"');
    expect(html).toContain("The limit is 1.5 MB");
  });
});

describe("compare disclosure", () => {
  it("offers two labelled id fields inside a disclosure beside the composer", () => {
    const html = render();
    expect(html).toContain("Compare two records");
    expect(html).toContain('for="assistant-compare-a"');
    expect(html).toContain('for="assistant-compare-b"');
    expect(html).toContain("First record");
    expect(html).toContain("Second record");
    expect(html).toContain('data-testid="assistant-compare-send"');
  });
});

describe("follow-ups and the brief", () => {
  it("offers a brief only for a completed, non-empty, non-stopped answer", () => {
    const html = render({ turns: [turn()] });
    expect(html).toContain('data-testid="assistant-brief"');
    expect(html).toContain("Download brief");
    expect(render({ turns: [turn({ settled: false })] })).not.toContain("Download brief");
    expect(render({ turns: [turn({ stopped: true })] })).not.toContain("Download brief");
    expect(render({ turns: [turn({ answer: "" })] })).not.toContain("Download brief");
  });

  it("derives follow-up chips from the ledger and offers none without it", () => {
    const html = render({ turns: [turn()] });
    expect(html).toContain('data-testid="assistant-followups"');
    expect(html).toContain('data-testid="assistant-followup-kev"');
    expect(html).toContain("When is CVE-2099-0001 due?");
    const noLedger = render({ turns: [turn({ tools: [] })] });
    expect(noLedger).not.toContain('data-testid="assistant-followups"');
  });
});

/** Every rendered tip panel, as text: the copy a reader gets on open or focus. */
function panelTexts(html: string): string[] {
  const host = document.createElement("div");
  host.innerHTML = html;
  return [...host.querySelectorAll(".ledger-helptip-panel")].map((node) => node.textContent ?? "");
}

describe("comprehension — the rail legend", () => {
  it("states the rail in one sentence pair instead of a paragraph", () => {
    const html = render({ turns: [turn()] });
    expect(html).toContain('data-testid="assistant-ledger-legend"');
    expect(html).toContain("Each line is one server-side lookup");
    expect(html).toContain("<strong>Rows</strong>");
    expect(html).toContain(
      "is how many records it returned; the chips are the records the answer can cite.",
    );
    // The three-sentence explanation is gone: the disclosure carries it now.
    expect(html).not.toContain("Every line is one tool call the server ran for this transcript.");
  });
});

describe("comprehension — the tips", () => {
  const allTips = render({
    turns: [turn({ unverified: ["CVE-2099-9999"] })],
    fault: budgetFault({ reason: "daily", resetAt: "2026-11-23T00:00:00.000Z" }),
  });

  it("names every term it explains, so each trigger has an accessible name", () => {
    for (const term of ["rows", "tool call", "cited", "unverified ids", "session / daily budget"]) {
      expect(allTips, term).toContain(`aria-label="About ${term}"`);
    }
  });

  it("explains meaning only: no variable, no file, no implementation", () => {
    const panels = panelTexts(allTips);
    expect(panels.length).toBe(5);
    for (const panel of panels) {
      expect(panel).not.toMatch(/AI_[A-Z_]+/);
      expect(panel).not.toMatch(/\.tsx?\b/);
      expect(panel).not.toMatch(/src\//);
    }
    expect(allTips).toContain("The panel names which one ran out.");
  });

  it("puts the cited tip on the citation summary it explains", () => {
    const host = document.createElement("div");
    host.innerHTML = allTips;
    const summary = host.querySelector('[data-testid="assistant-citations"] summary');
    expect(summary?.querySelector('[data-testid="assistant-tip-cited-trigger"]')).not.toBeNull();
    expect(summary?.textContent).toContain("records cited");
  });

  it("puts the unverified tip on the caution line and the budget tip on the fault meta", () => {
    const host = document.createElement("div");
    host.innerHTML = allTips;
    expect(
      host.querySelector(
        '[data-testid="assistant-unverified"] [data-testid="assistant-tip-unverified-trigger"]',
      ),
    ).not.toBeNull();
    expect(
      host.querySelector(
        '[data-testid="assistant-fault"] [data-testid="assistant-tip-budget-trigger"]',
      ),
    ).not.toBeNull();
  });
});

describe("comprehension — the empty state", () => {
  it("names what the desk can and cannot answer", () => {
    const html = render();
    expect(html).toContain('data-testid="assistant-empty-capacity"');
    expect(html).toContain(
      "Ask about records in this deployment — its catalogs, scores, and dates.",
    );
    expect(html).toContain("It will not write exploit code or give targeting advice.");
    // The suggestions themselves are unchanged: the edges are added, not swapped in.
    expect(html).toContain('data-testid="assistant-suggestion-kev-additions"');
  });

  it("keeps the same edge on a corpus with nothing to suggest", () => {
    const html = render({ suggestions: [] });
    expect(html).toContain('data-testid="assistant-suggestions-empty"');
    expect(html).toContain("nothing to suggest");
    expect(html).toContain("It will not write exploit code or give targeting advice.");
  });
});
