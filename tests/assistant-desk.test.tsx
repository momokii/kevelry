// The desk's retention behaviour, driven the way a reader drives it.
//
// The rule under test is one sentence: a screenshot sent with a question stays
// in context until it is removed. That is state — a thumbnail in the turn, a
// chip above the composer, and an `image` key on *every* request while it is
// held — so it is asserted against a mounted `AssistantDesk` with a stubbed
// `fetch`, not against a static render. The stream is a real SSE body parsed by
// the production parser; only the socket is replaced.
//
// What this file proves: the turn keeps a picture and never the payload, the
// chip appears only once a turn has carried the attachment, a follow-up request
// re-sends the same image, and removing the chip both stops the send and greys
// the historical thumbnail with a note. What it does not prove: that a live
// model reads the image. No test can prove that.
//
// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { AssistantDesk } from "../src/components/assistant/AssistantDesk";

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

describe("the screenshot stays in the turn and in context", () => {
  it("renders the attached image inside the question block, with alt text", async () => {
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
    expect(shot?.getAttribute("data-in-context")).toBe("true");
    // Still in context, so there is nothing to explain away.
    expect(shot?.querySelector('[data-testid="assistant-shot-detached"]')).toBeNull();

    // The summary names the file, and the name is text — never a data URL.
    const summary = shot?.querySelector("summary");
    expect(summary?.textContent).toContain("advisory.png");
    for (const attribute of ["alt", "title", "aria-label"]) {
      for (const node of shot?.querySelectorAll(`[${attribute}]`) ?? []) {
        expect(node.getAttribute(attribute) ?? "").not.toContain("data:");
      }
    }

    // The request that carried it did carry it, once.
    expect(bodies).toHaveLength(1);
    const image = bodies[0]?.image as { dataUrl?: string } | undefined;
    expect(image?.dataUrl).toBe(thumb?.getAttribute("src"));
    // Nothing about the image reaches a log: not the payload, not the base64.
    for (const call of consoleSpy.mock.calls) {
      expect(call.join(" ")).not.toContain("data:");
    }
    consoleSpy.mockRestore();
  });

  it("shows the context chip only once a turn has carried the attachment", async () => {
    await attach(pngFile("shot.png"));
    // Staged, not sent: the intake preview is the whole story, no second chip.
    expect(chip()).toBeNull();

    await ask("Which CVE ids are in this screenshot?");
    const row = chip();
    expect(row).not.toBeNull();
    expect(row?.textContent).toContain("screenshot in context");
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

  it("re-sends the same image on every later turn while it is in context", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");
    await ask("And which of those are in KEV?");

    expect(bodies).toHaveLength(2);
    const first = (bodies[0]?.image as { dataUrl?: string } | undefined)?.dataUrl;
    const second = (bodies[1]?.image as { dataUrl?: string } | undefined)?.dataUrl;
    expect(first?.startsWith("data:image/png;base64,")).toBe(true);
    // Retention, stated as the request it produces: the follow-up carries it.
    expect(second).toBe(first);
    // Both turns keep their own record of it.
    expect(host.querySelectorAll('[data-testid="assistant-shot"]')).toHaveLength(2);
    expect(chip()).not.toBeNull();
  });

  it("removing the chip stops the send and marks the thumbnail out of context", async () => {
    await attach(pngFile());
    await ask("Which CVE ids are in this screenshot?");

    const remove = chip()?.querySelector<HTMLButtonElement>(
      '[data-testid="assistant-image-context-remove"]',
    );
    await act(async () => {
      remove?.click();
    });
    await flush();

    // (a) the send stops.
    expect(chip()).toBeNull();
    await ask("And which of those are in KEV?");
    expect(bodies).toHaveLength(2);
    expect(Object.hasOwn(bodies[1] ?? {}, "image")).toBe(false);

    // (b) the historical thumbnail stays, greyed, with the reason in words.
    const shot = host.querySelector('[data-testid="assistant-shot"]');
    expect(shot).not.toBeNull();
    expect(shot?.getAttribute("data-in-context")).toBe("false");
    expect(shot?.querySelector('[data-testid="assistant-shot-detached"]')?.textContent).toBe(
      "No longer in context — this screenshot is not sent with later questions.",
    );
    // The turn that never carried one renders no thumbnail at all.
    expect(host.querySelectorAll('[data-testid="assistant-shot"]')).toHaveLength(1);
  });
});
