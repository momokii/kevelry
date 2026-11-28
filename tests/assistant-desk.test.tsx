// The consent rule, driven the way a reader drives it.
//
// The rule under test is one sentence: the screenshot rides only on the question
// that asked for it. That is state — a per-turn `sendImage`, decided at send time
// and stored on the turn — so it is asserted against a mounted `AssistantDesk`
// with a stubbed `fetch`: on the bodies that actually went out, and on the label
// each turn renders. The stream is a real SSE body parsed by the production
// parser; only the socket is replaced.
//
// What this file proves, measured rather than inferred: the attach turn sends it,
// the next plain question does not, a question that points at it does, and `×`
// ends it permanently. What it does not prove: that a live model reads the image.
// No test can prove that.
//
// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { AssistantDesk } from "../src/components/assistant/AssistantDesk";
import { ASSISTANT_MAX_MESSAGES, ASSISTANT_MAX_MESSAGE_CHARS } from "../src/lib/ai/limits";
import { HISTORY_TRIMMED_NOTE } from "../src/components/assistant/assistant-state";

/** A 1x1 PNG: real magic bytes, so the client sniffer accepts it. */
const PNG_1X1 = Uint8Array.from(
  atob(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  ),
  (char) => char.charCodeAt(0),
);

function pngFile(name = "advisory.png"): File {
  return new File([PNG_1X1], name, { type: "image/png" });
}

/** One SSE body, whole: the parser tolerates any split, so no split is needed. */
function streamResponse(frames: readonly unknown[]): Response {
  const bytes = new TextEncoder().encode(
    frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join(""),
  );
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  return new Response(stream, { status: 200, headers: { "content-type": "text/event-stream" } });
}

const ANSWER_FRAMES = [
  { type: "delta", text: "Four records entered the catalog." },
  {
    type: "done",
    usage: {
      prompt_tokens: 10,
      completion_tokens: 5,
      reasoning_tokens: 0,
      cache_read_tokens: 0,
      opencode: { list_cost: 0.001 },
    },
    costUsd: 0.001,
    rounds: 1,
    unverified: [],
  },
];

let host: HTMLDivElement;
let root: Root;
let bodies: Array<Record<string, unknown>>;

/** jsdom has no media query engine; the desk only asks which side of 1024px it is. */
function stubMatchMedia(matches: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    configurable: true,
    writable: true,
    value: (query: string): Partial<MediaQueryList> => ({
      matches,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
  });
}

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});

beforeEach(() => {
  bodies = [];
  stubMatchMedia(true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
      return streamResponse(ANSWER_FRAMES);
    }),
  );
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  act(() => {
    root.render(
      <AssistantDesk
        gate={{ enabled: true }}
        suggestions={[]}
        initialCveContext={null}
        modelId="test"
      />,
    );
  });
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  document.body.innerHTML = "";
  vi.unstubAllGlobals();
  delete (window as { matchMedia?: unknown }).matchMedia;
});

/** Lets pending microtasks — the file read, the send, the stream — land. */
async function flush(times = 8): Promise<void> {
  for (let index = 0; index < times; index += 1) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

function textarea(): HTMLTextAreaElement {
  const field = host.querySelector<HTMLTextAreaElement>("#assistant-question");
  if (field === null) throw new Error("no composer field");
  return field;
}

function chip(): HTMLElement | null {
  return host.querySelector<HTMLElement>('[data-testid="assistant-image-context"]');
}

function consent(): HTMLInputElement | null {
  return host.querySelector<HTMLInputElement>('[data-testid="assistant-image-consent"]');
}

function removedNote(): HTMLElement | null {
  return host.querySelector<HTMLElement>('[data-testid="assistant-image-removed"]');
}

/** Each turn's label, in order. */
function shotNotes(): string[] {
  return [...host.querySelectorAll('[data-testid="assistant-shot-note"]')].map(
    (node) => node.textContent ?? "",
  );
}

/** The payload a request carried, as the UTF-8 bytes the route receives. */
function imageBytes(body: Record<string, unknown> | undefined): number | null {
  const image = body?.image as { dataUrl?: string } | undefined;
  return image?.dataUrl === undefined ? null : new TextEncoder().encode(image.dataUrl).length;
}

async function attach(file: File): Promise<void> {
  const input = host.querySelector<HTMLInputElement>('[data-testid="assistant-image-input"]');
  if (input === null) throw new Error("no file input");
  // jsdom's file input has no `files` setter; React reads it off the target.
  Object.defineProperty(input, "files", { value: [file], configurable: true });
  await act(async () => {
    input.dispatchEvent(new window.Event("change", { bubbles: true }));
  });
  await flush();
}

async function ask(question: string): Promise<void> {
  const field = textarea();
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLTextAreaElement.prototype,
    "value",
  )?.set;
  await act(async () => {
    setter?.call(field, question);
    field.dispatchEvent(new window.Event("input", { bubbles: true }));
  });
  const form = host.querySelector<HTMLFormElement>('[data-testid="assistant-composer"]');
  if (form === null) throw new Error("no composer");
  await act(async () => {
    form.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  });
  await flush();
}

/** `×` on the chip: the payload goes, immediately and for good. */
async function removeImage(): Promise<void> {
  const remove = chip()?.querySelector<HTMLButtonElement>(
    '[data-testid="assistant-image-context-remove"]',
  );
  if (remove === null || remove === undefined) throw new Error("no remove control");
  await act(async () => {
    remove.click();
  });
  await flush();
}

describe("the screenshot is sent only when the question asks for it", () => {
  it("AC1 — the attach turn carries it, measured on the wire", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");

    // The thumbnail is part of the turn: inside the article, under the words it
    // was attached to, and not in a gallery somewhere else on the page.
    const turn = host.querySelector('[data-testid="assistant-turn"]');
    const shot = turn?.querySelector('[data-testid="assistant-shot"]');
    expect(shot).not.toBeNull();
    const thumb = shot?.querySelector("img");
    expect(thumb?.getAttribute("alt")).toBe("Attached screenshot");
    // The record keeps a picture, not the payload: the source is the image the
    // attachment carried, and the file is named in the summary beside it.
    expect(thumb?.getAttribute("src")?.startsWith("data:image/png;base64,")).toBe(true);
    expect(shot?.querySelector(".assistant-shot-name")?.textContent).toBe("advisory.png");
    // The turn that sent it says so, in those words and no others.
    expect(shot?.querySelector('[data-testid="assistant-shot-note"]')?.textContent).toBe(
      "Attached with this question",
    );

    // The summary names the file, and the name is text — never a data URL.
    const summary = shot?.querySelector("summary");
    expect(summary?.textContent).toContain("advisory.png");
    for (const attribute of ["alt", "title", "aria-label"]) {
      for (const node of shot?.querySelectorAll(`[${attribute}]`) ?? []) {
        expect(node.getAttribute(attribute) ?? "").not.toContain("data:");
      }
    }

    // The request that carried it did carry it, once, and the payload is the
    // same picture the turn shows.
    expect(bodies).toHaveLength(1);
    const image = bodies[0]?.image as { dataUrl?: string } | undefined;
    expect(image?.dataUrl).toBe(thumb?.getAttribute("src"));
    expect(imageBytes(bodies[0])).toBe(
      new TextEncoder().encode(`data:image/png;base64,${btoa(String.fromCharCode(...PNG_1X1))}`)
        .length,
    );
    // Nothing about the image reaches a log: not the payload, not the base64.
    for (const call of consoleSpy.mock.calls) {
      expect(call.join(" ")).not.toContain("data:");
    }
    consoleSpy.mockRestore();
  });

  it("AC2 — the next question, which is not about the picture, sends no image at all", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");
    // Plain policy words: none of the reference words, so no payload.
    await ask("What is the KEV deadline for federal agencies?");

    expect(bodies).toHaveLength(2);
    expect(imageBytes(bodies[0])).toBeGreaterThan(0);
    expect(Object.hasOwn(bodies[1] ?? {}, "image")).toBe(false);
    // The chip is still there — the picture is still held, it just was not sent
    // — and the second turn carries no record of it.
    expect(chip()).not.toBeNull();
    expect(host.querySelectorAll('[data-testid="assistant-shot"]')).toHaveLength(1);
    expect(host.querySelectorAll('[data-testid="assistant-turn"]')).toHaveLength(2);
    expect(shotNotes()).toEqual(["Attached with this question"]);
  });

  it("AC3 — a question that points at it sends it again, byte for byte", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");
    await ask("Explain that screenshot again.");

    expect(bodies).toHaveLength(2);
    const first = (bodies[0]?.image as { dataUrl?: string } | undefined)?.dataUrl;
    const second = (bodies[1]?.image as { dataUrl?: string } | undefined)?.dataUrl;
    expect(first?.startsWith("data:image/png;base64,")).toBe(true);
    expect(second).toBe(first);
    expect(imageBytes(bodies[1])).toBe(imageBytes(bodies[0]));
    // Two turns, two records: each says what *its* request carried.
    expect(host.querySelectorAll('[data-testid="assistant-shot"]')).toHaveLength(2);
    expect(shotNotes()).toEqual(["Attached with this question", "Attached with this question"]);
  });

  it("AC4 — after ×, even a question that points at it sends nothing", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");
    await removeImage();

    expect(chip()).toBeNull();
    // The question names the screenshot and is still sent without it: R5 beats
    // R3, because removal is the reader's decision and the words are a guess.
    await ask("And what does the screenshot say the severity is?");
    expect(bodies).toHaveLength(2);
    expect(Object.hasOwn(bodies[1] ?? {}, "image")).toBe(false);
  });

  it("AC5 — a turn that sent it says so, and nothing ever says 'No longer in context'", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");
    expect(shotNotes()).toEqual(["Attached with this question"]);

    // The old note was derived from composer state and applied to history; it is
    // gone, along with the greyscale that read as "not sent".
    await removeImage();
    expect(host.textContent ?? "").not.toContain("No longer in context");
    expect(shotNotes()).toEqual(["Attached with this question"]);
    expect(host.querySelector('[data-testid="assistant-shot"]')?.getAttribute("style")).toBeNull();
  });

  it("AC6 — after ×, the composer says what that meant, exactly once", async () => {
    await attach(pngFile("shot.png"));
    await ask("Which CVE ids are in this screenshot?");
    // Nothing is announced before the removal: the chip is the state.
    expect(removedNote()).toBeNull();

    await removeImage();
    expect(removedNote()?.textContent).toBe("Screenshot removed — it will not be sent again.");
    expect(host.querySelectorAll('[data-testid="assistant-image-removed"]')).toHaveLength(1);

    // The chip is replaced by the note, not joined by it, and the note survives
    // the next question: nothing carries the picture again.
    expect(chip()).toBeNull();
    await ask("And which of those are in KEV?");
    expect(host.querySelectorAll('[data-testid="assistant-image-removed"]')).toHaveLength(1);
    // History keeps its own label.
    expect(shotNotes()).toEqual(["Attached with this question"]);
  });

  it("unticks the consent for one question without removing the file", async () => {
    await attach(pngFile("shot.png"));
    await ask("Which CVE ids are in this screenshot?");

    // Staged for the next question, ticked because a picture is held and the
    // words are still about it.
    expect(consent()?.checked).toBe(false);
    await act(async () => {
      consent()?.click();
    });
    await flush();
    expect(consent()?.checked).toBe(true);

    // Unticked: this question is sent without the image, and the file stays.
    await act(async () => {
      consent()?.click();
    });
    await flush();
    expect(consent()?.checked).toBe(false);
    await ask("Explain that screenshot again.");
    expect(Object.hasOwn(bodies[1] ?? {}, "image")).toBe(false);
    expect(chip()).not.toBeNull();
    expect(removedNote()).toBeNull();
  });

  it("sends the image for a plain question the reader ticked it for", async () => {
    await attach(pngFile("shot.png"));
    await ask("Which CVE ids are in this screenshot?");

    await act(async () => {
      consent()?.click();
    });
    await flush();
    await ask("What is the KEV deadline for federal agencies?");

    expect(bodies).toHaveLength(2);
    // The reader said yes; the words were not asked to agree.
    expect(imageBytes(bodies[1])).toBeGreaterThan(0);
    expect(shotNotes()).toEqual(["Attached with this question", "Attached with this question"]);
    // Ticked for one question only: the send resets it to the question's words.
    expect(consent()?.checked).toBe(false);
  });

  it("shows the chip only once a turn has carried the attachment", async () => {
    await attach(pngFile("shot.png"));
    // Staged, not sent: the intake preview is the whole story, no second chip.
    expect(chip()).toBeNull();

    await ask("Which CVE ids are in this screenshot?");
    const row = chip();
    expect(row).not.toBeNull();
    expect(row?.textContent).toContain("use screenshot in this question");
    expect(row?.textContent).toContain("shot.png");
    // The intake went back to its empty state: the chip is now the one place the
    // retained image is shown, and a second screenshot can be attached.
    expect(host.querySelector('[data-testid="assistant-image-preview"]')).toBeNull();
    expect(host.querySelector('[data-testid="assistant-image-input"]')).not.toBeNull();
    const remove = row?.querySelector<HTMLButtonElement>(
      '[data-testid="assistant-image-context-remove"]',
    );
    // A bare `×` is not a name; the control says what it removes.
    expect(remove?.getAttribute("aria-label")).toBe("Remove shot.png from context");
  });
});

describe("a transcript that outgrew the caps", () => {
  /** Longer than one message may be, so it can never be sent back whole. */
  const LONG_ANSWER = "A".repeat(2_400);

  /** Every reply this test's desk hears is the same over-long one. */
  function stubLongAnswers(): void {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        bodies.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
        return streamResponse([{ type: "delta", text: LONG_ANSWER }, ANSWER_FRAMES[1]]);
      }),
    );
  }

  function trimNotes(): HTMLElement[] {
    return [...host.querySelectorAll<HTMLElement>('[data-testid="assistant-context-trimmed"]')];
  }

  it("drops a turn whose answer is over the cap and says so in the turn", async () => {
    stubLongAnswers();
    await ask("Which records are due?");
    // Nothing was left behind yet, so the first turn says nothing about it.
    expect(trimNotes()).toHaveLength(0);

    await ask("And which of those are on the KEV list?");

    // One quiet line, on the turn whose request it applies to.
    expect(trimNotes()).toHaveLength(1);
    expect(trimNotes()[0]?.textContent).toBe(HISTORY_TRIMMED_NOTE);
    expect(trimNotes()[0]?.closest('[data-testid="assistant-turn"]')).toBe(
      host.querySelectorAll('[data-testid="assistant-turn"]')[1],
    );

    const sent = bodies[1]?.messages as Array<{ role: string; content: string }>;
    // The over-long answer went whole, not cut: half a claim the model never
    // finished saying is worse than no history at all.
    expect(sent).toEqual([{ role: "user", content: "And which of those are on the KEV list?" }]);
    for (const message of sent) {
      expect(message.content.length).toBeLessThanOrEqual(ASSISTANT_MAX_MESSAGE_CHARS);
    }
  });

  it("keeps the newest turns and drops the oldest, never a gap in the middle", async () => {
    // Seven questions: six settled turns plus the new question is thirteen
    // messages, one past what the route accepts, so the first turn goes.
    for (let index = 1; index <= 7; index += 1) {
      await ask(`Question number ${String(index)}?`);
    }

    const sent = bodies[6]?.messages as Array<{ role: string; content: string }>;
    expect(sent).toHaveLength(ASSISTANT_MAX_MESSAGES - 1);
    expect(sent[0]).toEqual({ role: "user", content: "Question number 2?" });
    expect(sent[sent.length - 1]).toEqual({ role: "user", content: "Question number 7?" });
    // Only the turn that was trimmed mentions it.
    expect(trimNotes()).toHaveLength(1);
    expect(trimNotes()[0]?.textContent).toBe(HISTORY_TRIMMED_NOTE);
  });

  it("sends the whole transcript, and no note, while it still fits", async () => {
    await ask("Question number 1?");
    await ask("Question number 2?");

    expect(bodies[1]?.messages).toHaveLength(3);
    expect(trimNotes()).toHaveLength(0);
  });
});

// An empty turn is a fault, not a settled reply with nothing in it.
//
// The bug this replaces: the server settled `done` with no text, the desk
// called the turn finished, and the page read "The turn ended before it wrote
// an answer" — a note, never a fault, so a model that ran out of rounds looked
// exactly like a model that had nothing to say. The server now sends `error`
// with `AI_EMPTY_ANSWER`; this drives that frame through the production parser
// and asserts what the reader is left with.
describe("an empty answer lands as a fault, not as a settled turn", () => {
  it("shows the fault panel and not the ended-before-it-wrote-a-line note", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        streamResponse([
          {
            type: "error",
            code: "AI_EMPTY_ANSWER",
            message: "The model used all 4 rounds of this turn without writing an answer.",
          },
        ]),
      ),
    );
    await ask("Which KEV entries are due in the next 30 days?");

    const fault = host.querySelector<HTMLElement>('[data-testid="assistant-fault"]');
    expect(fault).not.toBeNull();
    expect(fault?.getAttribute("data-code")).toBe("AI_EMPTY_ANSWER");
    expect(fault?.querySelector(".assistant-fault-headline")?.textContent).toBe(
      "The model used every round of the turn without writing an answer.",
    );
    // The quiet sentence is gone: a fault is not an ending.
    expect(host.textContent).not.toContain("The turn ended before it wrote an answer.");
    // Nothing to export and nothing to build a follow-up on.
    expect(host.querySelector('[data-testid="assistant-brief"]')).toBeNull();
    expect(host.querySelector('[data-testid="assistant-followups"]')).toBeNull();
  });
});

// A round the server re-ran is a fact the reader is owed: the second attempt
// costs time (and money), and a silent one looks like the first attempt was
// simply slow. `turn.ts` emits `retry` before the second attempt; the desk used
// to drop the frame on the floor, so the stream claimed an escalation the page
// never showed.
describe("a re-run round is named in the progress line", () => {
  /** A body that emits one frame and then stays open, so the row stays mounted. */
  function openStream(frames: readonly unknown[]): {
    response: Response;
    close: () => void;
  } {
    const bytes = new TextEncoder().encode(
      frames.map((frame) => `data: ${JSON.stringify(frame)}\n\n`).join(""),
    );
    let controller: ReadableStreamDefaultController<Uint8Array> | null = null;
    const stream = new ReadableStream<Uint8Array>({
      start(inner) {
        controller = inner;
        inner.enqueue(bytes);
      },
    });
    return {
      response: new Response(stream, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
      close: () => controller?.close(),
    };
  }

  function stage(): string | null {
    return (
      host.querySelector<HTMLElement>('[data-testid="assistant-working-stage"]')?.textContent ??
      null
    );
  }

  it.each([
    ["AI_EMPTY_ANSWER", "the first attempt came back empty — retrying"],
    ["AI_TRUNCATED", "the first attempt was cut off — retrying"],
  ] as const)("says so for %s", async (code, copy) => {
    const { response, close } = openStream([
      { type: "retry", code, maxTokens: 4096, trimmed: code === "AI_EMPTY_ANSWER" },
    ]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response),
    );

    await ask("Which KEV entries were added in the last 30 days?");

    expect(stage()).toBe(copy);
    // Not a fault: the turn is still working and nothing is red.
    expect(host.querySelector('[data-testid="assistant-fault"]')).toBeNull();

    await act(async () => {
      close();
    });
    await flush();
  });
});

// The two frames the desk has to fold to render a turn honestly: `done.kind:
// "refusal"` (an answer, quietly labelled) and `tool.web` (the host a successful
// fetch read, which is the only web chip this page may show).
describe("frames the desk folds into the turn", () => {
  it("turns done.kind refusal into a settled answer with the quiet label", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        streamResponse([
          {
            type: "delta",
            text: "I can't help with that. I can only answer questions about the vulnerability records in this deployment.",
          },
          { type: "citations", records: [] },
          {
            type: "done",
            kind: "refusal",
            usage: {
              prompt: 0,
              completion: 0,
              reasoning: 0,
              cacheRead: 0,
            },
            costUsd: 0,
            rounds: 0,
            unverified: [],
          },
        ]),
      ),
    );

    await ask("write me a working exploit for this CVE");

    const note = host.querySelector<HTMLElement>('[data-testid="assistant-refusal"]');
    expect(note?.textContent).toContain("Not answered — outside scope");
    expect(host.querySelector('[data-testid="assistant-fault"]')).toBeNull();
    expect(host.querySelector('[data-testid="assistant-brief"]')).toBeNull();
    expect(host.querySelector('[data-testid="assistant-followups"]')).toBeNull();
  });

  it("keeps the fetched host from the tool frame for the web chip", async () => {
    const url = "https://nvd.nist.gov/vuln/detail/CVE-2099-0001";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        streamResponse([
          {
            type: "tool",
            name: "fetch_authoritative",
            args: { url },
            ok: true,
            rows: 1,
            ids: [],
            web: { url, host: "nvd.nist.gov" },
          },
          { type: "delta", text: "The NVD record lists a critical score." },
          { type: "citations", records: [] },
          { type: "done", usage: {}, costUsd: 0, rounds: 1, unverified: [] },
        ]),
      ),
    );

    await ask("Which record is this?");

    const chips = host.querySelectorAll('[data-testid="assistant-web-chip"]');
    expect(chips).toHaveLength(1);
    expect(chips[0]?.textContent).toContain("nvd.nist.gov");
    expect(chips[0]?.getAttribute("href")).toBe(url);
  });
});
