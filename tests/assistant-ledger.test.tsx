// The rail's density rules: a hierarchy of disclosures, not a scrollbar.
//
// Three things are pinned here, because each one is a claim the reader can check
// only by looking: a call shows six chips and says how many more it has; the row
// label never claims ids the server did not send; and the rail shows three calls
// yet never hides an empty or failed one. Expansion is state, so these tests
// mount the component rather than render a string — a `+N more` that does not
// open is exactly the failure a static snapshot cannot see.
//
// @vitest-environment jsdom

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  AssistantLedger,
  LEDGER_CHIPS_PER_CALL,
} from "../src/components/assistant/AssistantLedger";
import { AssistantView, type AssistantViewProps } from "../src/components/assistant/AssistantView";
import type { AssistantToolLine, AssistantTurn } from "../src/components/assistant/assistant-state";

beforeAll(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});

const mounts: { root: Root; host: HTMLDivElement }[] = [];

function mount(node: ReactNode): HTMLDivElement {
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  act(() => root.render(node));
  mounts.push({ root, host });
  return host;
}

afterEach(() => {
  for (const { root } of mounts.splice(0)) {
    act(() => root.unmount());
  }
  document.body.innerHTML = "";
});

/** `count` synthetic ids, zero-padded so their order is the array's order. */
function ids(count: number): string[] {
  return Array.from(
    { length: count },
    (_, index) => `CVE-2099-${String(index + 1).padStart(4, "0")}`,
  );
}

function line(overrides: Partial<AssistantToolLine> = {}): AssistantToolLine {
  return {
    id: "tool-1",
    name: "search_cves",
    args: "q=log4j",
    rows: 4,
    ok: true,
    ids: ids(4),
    ...overrides,
  };
}

function turn(tools: AssistantToolLine[], overrides: Partial<AssistantTurn> = {}): AssistantTurn {
  return {
    id: "turn-1",
    question: "Which KEV entries were added in the last 30 days?",
    answer: "Four records entered the catalog.",
    settled: true,
    stopped: false,
    citations: tools.flatMap((tool) => tool.ids),
    unverified: [],
    tools,
    aboutCve: null,
    ...overrides,
  };
}

function renderLedger(turns: AssistantTurn[]): HTMLDivElement {
  return mount(<AssistantLedger turns={turns} open onToggle={() => undefined} />);
}

function rowLabels(host: HTMLDivElement): string[] {
  return [...host.querySelectorAll<HTMLElement>('[data-testid="assistant-ledger-rows"]')].map(
    (node) => node.textContent ?? "",
  );
}

function chipCount(host: HTMLDivElement): number {
  return host.querySelectorAll('[data-testid="assistant-ledger-chips"] li').length;
}

function button(host: HTMLDivElement, testId: string): HTMLButtonElement {
  const found = host.querySelector<HTMLButtonElement>(`[data-testid="${testId}"]`);
  if (found === null) throw new Error(`no ${testId} in the rail`);
  return found;
}

describe("chips per call", () => {
  it("shows six chips and reveals the rest in place", () => {
    const host = renderLedger([turn([line({ rows: 25, ids: ids(25) })])]);
    expect(LEDGER_CHIPS_PER_CALL).toBe(6);
    expect(chipCount(host)).toBe(6);

    const more = button(host, "assistant-ledger-chip-more");
    expect(more.textContent).toBe("+19 more");
    expect(more.getAttribute("aria-expanded")).toBe("false");

    act(() => more.click());
    // Same list, same order, only longer: nothing is opened elsewhere.
    expect(chipCount(host)).toBe(25);
    expect(host.querySelectorAll('[data-testid="assistant-ledger-chips"]')).toHaveLength(1);
    expect(button(host, "assistant-ledger-chip-more").getAttribute("aria-expanded")).toBe("true");

    act(() => button(host, "assistant-ledger-chip-more").click());
    expect(chipCount(host)).toBe(6);
  });

  it("keeps the chip order stable and labels the control with what it hides", () => {
    const host = renderLedger([turn([line({ rows: 8, ids: ids(8) })])]);
    expect(button(host, "assistant-ledger-chip-more").textContent).toBe("+2 more");
    act(() => button(host, "assistant-ledger-chip-more").click());
    const rendered = [
      ...host.querySelectorAll('[data-testid="assistant-ledger-chips"] .assistant-chip-id'),
    ].map((node) => node.textContent);
    expect(rendered).toEqual(ids(8));
  });

  it("offers no disclosure when every id already fits", () => {
    const host = renderLedger([turn([line()])]);
    expect(chipCount(host)).toBe(4);
    expect(host.querySelector('[data-testid="assistant-ledger-chip-more"]')).toBeNull();
  });
});

describe("the row label", () => {
  it("states the count alone when every id came back", () => {
    const host = renderLedger([turn([line({ rows: 4, ids: ids(4) })])]);
    expect(rowLabels(host)).toEqual(["4 rows"]);
  });

  it("prints the ids sample beside the real count when they differ", () => {
    const host = renderLedger([turn([line({ rows: 50, ids: ids(12) })])]);
    expect(rowLabels(host)).toEqual(["50 rows · 12 ids available"]);
  });

  it("says no rows for an empty result and failed for a call that did not run", () => {
    const host = renderLedger([
      turn([line({ id: "a", rows: 0, ids: [] }), line({ id: "b", rows: 0, ids: [], ok: false })]),
    ]);
    expect(rowLabels(host)).toEqual(["no rows", "failed"]);
  });

  it("does not claim ids when a non-empty call returned none", () => {
    const host = renderLedger([turn([line({ rows: 3, ids: [] })])]);
    expect(rowLabels(host)).toEqual(["3 rows · no ids available"]);
    expect(chipCount(host)).toBe(0);
  });

  it("counts the singular row", () => {
    const host = renderLedger([turn([line({ rows: 1, ids: ids(1) })])]);
    expect(rowLabels(host)).toEqual(["1 row"]);
  });
});

describe("calls per rail", () => {
  function sevenCalls(): AssistantTurn[] {
    return [
      turn(
        [
          line({ id: "c1" }),
          line({ id: "c2" }),
          line({ id: "c3" }),
          line({ id: "c4" }),
          // Position five, empty: invisible would be a lie about the evidence.
          line({ id: "c5", name: "epss_history", rows: 0, ids: [] }),
          line({ id: "c6" }),
          line({ id: "c7", name: "cwe_lookup", ok: false, rows: 0, ids: [] }),
        ],
        { citations: [] },
      ),
    ];
  }

  it("shows three calls, then every call behind one control", () => {
    const host = renderLedger(sevenCalls());
    expect(host.querySelectorAll('[data-testid="assistant-ledger-entry"]')).toHaveLength(5);

    const control = button(host, "assistant-ledger-calls-more");
    expect(control.textContent).toBe("See all 7 calls");
    expect(control.getAttribute("aria-expanded")).toBe("false");

    act(() => control.click());
    expect(host.querySelectorAll('[data-testid="assistant-ledger-entry"]')).toHaveLength(7);
    expect(button(host, "assistant-ledger-calls-more").textContent).toBe("Show fewer calls");
  });

  it("pins a no-rows call and a failed call above the control while collapsed", () => {
    const host = renderLedger(sevenCalls());
    expect(rowLabels(host)).toEqual(["4 rows", "4 rows", "4 rows", "no rows", "failed"]);
    // Pinned entries keep their transcript order: 1, 2, 3, then 5 and 7.
    expect(rowLabels(host).slice(3)).toEqual(["no rows", "failed"]);
  });

  it("offers no call control when three calls or fewer exist", () => {
    const host = renderLedger([turn([line({ id: "a" }), line({ id: "b" }), line({ id: "c" })])]);
    expect(host.querySelectorAll('[data-testid="assistant-ledger-entry"]')).toHaveLength(3);
    expect(host.querySelector('[data-testid="assistant-ledger-calls-more"]')).toBeNull();
  });
});

describe("the cited block", () => {
  function viewProps(overrides: Partial<AssistantViewProps> = {}): AssistantViewProps {
    return {
      gate: { enabled: true },
      suggestions: [],
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

  it("folds the turn's citations to one line that opens to the chips", () => {
    const host = mount(
      <AssistantView
        {...viewProps({
          turns: [turn([line({ rows: 15, ids: ids(15) })], { citations: ids(15) })],
        })}
      />,
    );
    const details = host.querySelector<HTMLDetailsElement>('[data-testid="assistant-citations"]');
    expect(details).not.toBeNull();
    expect(details?.open).toBe(false);
    expect(details?.querySelector("summary")?.textContent).toBe("15 records cited");

    act(() => details?.querySelector("summary")?.click());
    expect(details?.open).toBe(true);
    expect(host.querySelectorAll('[data-testid="assistant-citation"]')).toHaveLength(15);
  });

  it("counts one citation in the singular", () => {
    const host = mount(
      <AssistantView
        {...viewProps({ turns: [turn([line({ rows: 1, ids: ids(1) })], { citations: ids(1) })] })}
      />,
    );
    expect(host.querySelector('[data-testid="assistant-citations"] summary')?.textContent).toBe(
      "1 record cited",
    );
  });
});

describe("the rail's scrollbar", () => {
  it("sets no max-height and no overflow on the desktop ledger", async () => {
    const css = await readFile(resolve(process.cwd(), "app/ui.css"), "utf8");
    const base = /\.assistant-ledger \{([^}]*)\}/.exec(css);
    expect(base).not.toBeNull();
    const body = base?.[1] ?? "";
    expect(body).not.toMatch(/max-height/);
    expect(body).not.toMatch(/overflow/);
    // The sticky rail survives; only the inner scroll context is gone.
    expect(body).toMatch(/position: sticky/);
  });

  it("renders no inline scroll container around the ledger", () => {
    const html = renderToStaticMarkup(
      <AssistantLedger turns={[turn([line()])]} open onToggle={() => undefined} />,
    );
    expect(html).not.toMatch(/max-height|overflow/);
  });
});
