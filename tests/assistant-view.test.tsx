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
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AssistantView, type AssistantViewProps } from "../src/components/assistant/AssistantView";
import type { AssistantAttachment } from "../src/components/assistant/assistant-image";
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
    failed: false,
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
    sendImage: false,
    image: null,
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
    imageRemoved: false,
    sendImage: false,
    remainingSeconds: null,
    ledgerOpen: true,
    onDraftChange: () => undefined,
    onImagePick: () => undefined,
    onImageConsentChange: () => undefined,
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
    // The privacy line names the image as well as the transcript, because the
    // image is now held for the session: a reload clears both.
    expect(html).toContain(
      "The transcript and any screenshot live in this tab and nowhere else — a reload starts clean, and neither is written to this browser",
    );
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

  it("keeps the stage and the counter in one polite region, with the counter hidden", () => {
    const html = render({
      turns: [turn({ settled: false, answer: "" })],
      status: "streaming",
      activity: "reading the record · 1 record…",
    });
    const host = document.createElement("div");
    host.innerHTML = html;
    const region = host.querySelector('[data-testid="assistant-working"]');
    expect(region?.getAttribute("role")).toBe("status");
    expect(region?.getAttribute("aria-live")).toBe("polite");
    const stage = region?.querySelector('[data-testid="assistant-working-stage"]');
    const elapsed = region?.querySelector('[data-testid="assistant-working-elapsed"]');
    expect(stage?.textContent).toBe("reading the record · 1 record…");
    // The accessible text of the region is the stage alone: a tick every quarter
    // second must not be announced.
    expect(elapsed?.getAttribute("aria-hidden")).toBe("true");
    expect(region?.textContent).toBe("reading the record · 1 record…0.0sStop");
    // Stop keeps its own accessible name, inside the region and beside the counter.
    const stop = region?.querySelector('[data-testid="assistant-stop"]');
    expect(stop?.textContent).toBe("Stop");
    expect(stage?.compareDocumentPosition(elapsed as Node)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
  });

  it("changes the stage on the first delta and has no second activity line in the turn", () => {
    const toolStage = render({
      turns: [turn({ settled: false, answer: "" })],
      status: "streaming",
      activity: "reading the record · 1 record…",
    });
    expect(toolStage).toContain("reading the record · 1 record…");
    const proseStage = render({
      turns: [turn({ settled: false, answer: "Four" })],
      status: "streaming",
    });
    expect(proseStage).toContain("writing…");
    // One working region on the screen: the turn's own activity line is gone.
    expect(toolStage).not.toContain('data-testid="assistant-activity"');
  });

  it("shows the moving progress rule only before any text arrives", () => {
    const withRule = render({
      turns: [turn({ settled: false, answer: "", citations: [] })],
      status: "streaming",
      activity: "reading the record · 1 record…",
    });
    expect(withRule).toContain('data-testid="assistant-progress"');
    expect(withRule).toContain('class="assistant-progress is-running"');
    const withText = render({
      turns: [turn({ settled: false, answer: "Four" })],
      status: "streaming",
    });
    expect(withText).not.toContain('data-testid="assistant-progress"');
  });

  it("marks the composer as working while a turn streams", () => {
    const streaming = render({
      turns: [turn({ settled: false, answer: "" })],
      status: "streaming",
      activity: "reading the record · 1 record…",
    });
    expect(streaming).toContain("assistant-composer is-working");
    expect(render()).not.toContain("is-working");
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

  it("marks a failed turn's partial answer as incomplete, not as an answer", () => {
    // A dropped stream leaves prose on screen. It must not pass for a finished
    // thought: no export of a half-answer, no follow-up built on it, and one
    // sentence saying where it stopped.
    const html = render({ turns: [turn({ failed: true, answer: "Four records " })] });
    expect(html).toContain('data-testid="assistant-incomplete"');
    expect(html).toContain("Incomplete: the answer stopped before it finished.");
    expect(html).toContain("Four records ");
    expect(html).not.toContain('data-testid="assistant-brief"');
    expect(html).not.toContain('data-testid="assistant-followups"');
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
        id: 1,
        thumb: "data:image/png;base64,iVBORw0KGgo=",
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

/** A retained attachment, shaped exactly as the desk holds it. */
function attachment(overrides: Partial<AssistantAttachment> = {}): AssistantAttachment {
  return {
    id: 1,
    dataUrl: "data:image/png;base64,iVBORw0KGgo=",
    thumb: "data:image/webp;base64,UklGRg==",
    name: "advisory.png",
    size: 41_000,
    mime: "image/png",
    ...overrides,
  };
}

describe("the screenshot in the turn", () => {
  const sent = turn({
    sendImage: true,
    image: {
      id: 1,
      name: "advisory.png",
      mime: "image/png",
      size: 41_000,
      thumb: "data:image/webp;base64,UklGRg==",
    },
  });

  it("renders the record's thumbnail inside the question, named in words", () => {
    const host = document.createElement("div");
    host.innerHTML = render({ turns: [sent], image: attachment() });
    const article = host.querySelector('[data-testid="assistant-turn"]');
    // The thumbnail is part of the question block: after the words, before the
    // answer, and not floating anywhere else on the page.
    const shot = article?.querySelector('[data-testid="assistant-shot"]') ?? null;
    const question = article?.querySelector(".assistant-question") ?? null;
    const answer = article?.querySelector(".assistant-answer") ?? null;
    if (shot === null || question === null || answer === null) {
      throw new Error("missing turn markup");
    }
    expect(question.compareDocumentPosition(shot) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(shot.compareDocumentPosition(answer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    // The expand affordance is a native disclosure, and the picture carries the
    // one alt text the reader needs.
    expect(shot.querySelector("details")).not.toBeNull();
    const thumb = shot.querySelector(".assistant-shot-thumb");
    expect(thumb?.getAttribute("alt")).toBe("Attached screenshot");
    expect(thumb?.getAttribute("src")).toBe("data:image/webp;base64,UklGRg==");
    expect(shot.querySelector("summary")?.textContent).toContain("advisory.png");
    expect(shot.querySelector("summary")?.textContent).toContain("PNG");
    // The expanded copy is decoration: the summary already named it.
    expect(shot.querySelector(".assistant-shot-full-image")?.getAttribute("alt")).toBe("");
    // A thumbnail exists because this question's request carried the picture, so
    // the note states what happened rather than what is in context now.
    expect(shot.querySelector('[data-testid="assistant-shot-note"]')?.textContent).toBe(
      "Attached with this question",
    );
  });

  it("puts no data URL in a label, a title or an alt except the image source", () => {
    const host = document.createElement("div");
    host.innerHTML = render({ turns: [sent], image: attachment() });
    for (const attribute of ["alt", "title", "aria-label"]) {
      for (const node of host.querySelectorAll(`[${attribute}]`)) {
        expect(node.getAttribute(attribute) ?? "").not.toContain("data:");
      }
    }
  });

  it("renders nothing for a turn that carried no image", () => {
    const html = render({ turns: [turn()] });
    expect(html).not.toContain('data-testid="assistant-shot"');
    expect(html).not.toContain("Attached screenshot");
  });

  it("keeps its label after the image is removed, and never says it was not sent", () => {
    // The composer no longer holds the picture: that is a fact about the next
    // question, and it must not be projected backwards onto this one.
    const host = document.createElement("div");
    host.innerHTML = render({ turns: [sent], image: null, imageRemoved: true });
    const shot = host.querySelector('[data-testid="assistant-shot"]');
    expect(shot).not.toBeNull();
    expect(shot?.querySelector('[data-testid="assistant-shot-note"]')?.textContent).toBe(
      "Attached with this question",
    );
    expect(host.textContent ?? "").not.toContain("No longer in context");
    // The removal is said once, at the composer, where it changes a decision.
    expect(host.querySelectorAll('[data-testid="assistant-image-removed"]')).toHaveLength(1);
  });

  it("says nothing on a turn that did not carry it", () => {
    // A different image in context does not rewrite an earlier turn's record.
    const host = document.createElement("div");
    host.innerHTML = render({
      turns: [turn()],
      image: attachment({ id: 2, name: "other.png" }),
    });
    expect(host.querySelector('[data-testid="assistant-shot"]')).toBeNull();
    expect(host.querySelector('[data-testid="assistant-shot-note"]')).toBeNull();
  });
});

describe("the context chip above the composer", () => {
  const sent = turn({
    sendImage: true,
    image: {
      id: 1,
      name: "advisory.png",
      mime: "image/png",
      size: 41_000,
      thumb: "data:image/webp;base64,UklGRg==",
    },
  });

  it("names the file, carries the consent checkbox, and offers a remove with a real name", () => {
    const host = document.createElement("div");
    host.innerHTML = render({ turns: [sent], image: attachment(), sendImage: true });
    const chip = host.querySelector('[data-testid="assistant-image-context"]');
    expect(chip).not.toBeNull();
    expect(chip?.textContent).toContain("use screenshot in this question");
    expect(chip?.textContent).toContain("advisory.png");
    // The control is a native checkbox, and its label is the sentence beside it.
    const consent = chip?.querySelector<HTMLInputElement>(
      '[data-testid="assistant-image-consent"]',
    );
    expect(consent?.getAttribute("type")).toBe("checkbox");
    expect(consent?.checked).toBe(true);
    expect(chip?.querySelector("label")?.textContent).toBe("use screenshot in this question");
    const remove = chip?.querySelector('[data-testid="assistant-image-context-remove"]');
    expect(remove?.getAttribute("aria-label")).toBe("Remove advisory.png from context");
    // Above the field the next question is typed into, not below the fold.
    const field = host.querySelector("#assistant-question");
    if (chip === null || field === null) throw new Error("missing composer markup");
    expect(chip.compareDocumentPosition(field) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("shows the checkbox unticked when the next question will not carry it", () => {
    const host = document.createElement("div");
    host.innerHTML = render({ turns: [sent], image: attachment(), sendImage: false });
    const consent = host.querySelector<HTMLInputElement>('[data-testid="assistant-image-consent"]');
    expect(consent?.checked).toBe(false);
  });

  it("appears only once a turn has carried the attachment", () => {
    // Staged but not sent: the intake preview already names and removes it.
    expect(render({ image: attachment() })).not.toContain('data-testid="assistant-image-context"');
  });

  it("takes the intake's place instead of duplicating it", () => {
    // One screenshot is shown once: retained in the chip, the intake is empty
    // again and ready for the next one.
    const html = render({ turns: [sent], image: attachment() });
    expect(html).not.toContain('data-testid="assistant-image-preview"');
    expect(html).toContain('data-testid="assistant-image-input"');
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

describe("the working row counts on its own", () => {
  beforeAll(() => {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  });

  afterEach(() => {
    vi.useRealTimers();
    document.body.innerHTML = "";
  });

  /**
   * The counter is state, not markup, so it is mounted rather than rendered as a
   * string: a static render can only ever show its first value. Fake timers make
   * the interval deterministic, and `Date.now` is faked with them.
   */
  it("increments with the interval from send, and dies with the row on settle", () => {
    vi.useFakeTimers();
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);
    const counter = (): string | null =>
      host.querySelector('[data-testid="assistant-working-elapsed"]')?.textContent ?? null;

    act(() => {
      root.render(
        <AssistantView
          {...baseProps({
            turns: [turn({ settled: false, answer: "" })],
            status: "streaming",
            activity: "reading the record · 1 record…",
          })}
        />,
      );
    });
    expect(counter()).toBe("0.0s");

    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(counter()).toBe("0.2s");
    act(() => {
      vi.advanceTimersByTime(750);
    });
    expect(counter()).toBe("1.0s");
    // Past ten seconds the readout drops to whole seconds: an obviously long
    // wait does not need a digit that moves four times a second.
    act(() => {
      vi.advanceTimersByTime(11_000);
    });
    expect(counter()).toBe("12s");

    // Settling unmounts the row, and the interval with it: nothing ticks behind
    // an idle composer.
    act(() => {
      root.render(<AssistantView {...baseProps({ turns: [turn()] })} />);
    });
    expect(host.querySelector('[data-testid="assistant-working"]')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
    act(() => root.unmount());
  });
});

describe("what a screenshot is good for", () => {
  it("is a closed native disclosure with a 44px summary", () => {
    const host = document.createElement("div");
    host.innerHTML = render();
    const guide = host.querySelector('[data-testid="assistant-image-guide"]');
    expect(guide?.tagName).toBe("DETAILS");
    expect(guide?.hasAttribute("open")).toBe(false);
    expect(guide?.querySelector("summary")?.textContent).toBe("What works");
    // Beneath the attach control and above the format note: the guidance is one
    // line under the thing it explains.
    const pick = host.querySelector(".assistant-image-pick");
    const note = host.querySelector("#assistant-image-note");
    if (guide === null || pick === null || note === null) throw new Error("missing attach markup");
    expect(pick.compareDocumentPosition(guide) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(guide.compareDocumentPosition(note) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("names four sources that work and two that do not", () => {
    const html = render();
    const works = [
      "A vendor advisory page showing a CVE id",
      "An NVD or CVE record page",
      "A scanner report or ticket listing CVEs",
      "A PDF page screenshot that carries a CVE id",
    ];
    const useless = [
      "A game scoreboard or a photo",
      "A dashboard with no CVE id, vendor or product name",
    ];
    for (const text of [...works, ...useless]) expect(html).toContain(text);
    // Counted, so the copy cannot quietly shrink to one line later.
    expect(html.match(/<li>/g)?.length).toBeGreaterThanOrEqual(works.length + useless.length);
  });

  it("says the ids are checked against the dataset, and that a refusal is correct", () => {
    const html = render();
    expect(html).toContain(
      "The image is only used to find CVE ids. Each id is then checked against this dataset, and an id that does not resolve is reported as not here.",
    );
    expect(html).toContain(
      "If the image has no CVE id in it, the answer says so. That is the desk working, not a failure.",
    );
    expect(html).toContain("Does not work");
  });
});
