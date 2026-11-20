// The shared chart primitives carry the inspectable-data contract: the one
// tooltip, the value-never-depends-on-hover table, and the roving keyboard
// contract. None of them had an assertion of its own — the sparkline was only
// tested through `formatEpssPercent` — so each documented behaviour is pinned
// here. Placement is a layout effect and the keyboard contract is about real
// focus, so this file needs a document; the rest of the suite stays on node.
//
// @vitest-environment jsdom

import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { ChartTable, type ChartTableColumn } from "../src/components/charts/ChartTable";
import {
  ChartTooltip,
  anchorFromElement,
  type ChartTooltipAnchor,
} from "../src/components/charts/ChartTooltip";
import {
  useHoverFocusMarks,
  type HoverFocusMarks,
} from "../src/components/charts/useHoverFocusMarks";
import {
  useRovingMarkFocus,
  type RovingOrientation,
} from "../src/components/charts/useRovingMarkFocus";

/** Mirrors the constants in `ChartTooltip`, so a placement test reads as maths. */
const EDGE = 8;
const GAP = 12;
const TOOLTIP_WIDTH = 180;
const TOOLTIP_HEIGHT = 64;
/** A host wide enough that a mark can sit on either side of the tooltip. */
const WIDE_HOST = { width: 800, height: 300 };

beforeAll(() => {
  // jsdom has no layout engine: every box measures 0x0, so the placement math
  // would always land on its clamp and prove nothing. The two boxes the tooltip
  // reads are stubbed instead: the host gets instance values when it is created,
  // and the tooltip node (created by React during the mount) gets these defaults.
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", {
    configurable: true,
    get(this: HTMLElement) {
      return this.classList.contains("chart-tooltip") ? TOOLTIP_WIDTH : 0;
    },
  });
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
    configurable: true,
    get(this: HTMLElement) {
      return this.classList.contains("chart-tooltip") ? TOOLTIP_HEIGHT : 0;
    },
  });
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
});

interface SizedBox {
  width: number;
  height: number;
}

interface Mounted {
  host: HTMLDivElement;
  rerender: (node: ReactNode) => void;
}

const mounts: { root: Root; host: HTMLDivElement }[] = [];

/** Mount into a host we own, so `clientWidth`/`clientHeight` exist before the
 * tooltip's layout effect measures them. jsdom returns null from `offsetParent`,
 * so the tooltip falls back to its `parentElement` — this host. */
function mount(node: ReactNode, box: SizedBox = WIDE_HOST): Mounted {
  const host = document.createElement("div");
  Object.defineProperty(host, "clientWidth", { configurable: true, value: box.width });
  Object.defineProperty(host, "clientHeight", { configurable: true, value: box.height });
  document.body.append(host);
  const root = createRoot(host);
  act(() => root.render(node));
  mounts.push({ root, host });
  return { host, rerender: (next) => act(() => root.render(next)) };
}

afterEach(() => {
  for (const { root, host } of mounts) {
    act(() => root.unmount());
    host.remove();
  }
  mounts.length = 0;
});

function mustFind(parent: ParentNode, selector: string): HTMLElement {
  const found = parent.querySelector(selector);
  if (!(found instanceof HTMLElement)) throw new Error(`missing element: ${selector}`);
  return found;
}

interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

function tooltipBox(tooltip: HTMLElement): Box {
  return {
    left: Number.parseFloat(tooltip.style.left),
    top: Number.parseFloat(tooltip.style.top),
    width: TOOLTIP_WIDTH,
    height: TOOLTIP_HEIGHT,
  };
}

function markBox(anchor: ChartTooltipAnchor): Box {
  return {
    left: anchor.x,
    top: anchor.y,
    width: anchor.width ?? 0,
    height: anchor.height ?? 0,
  };
}

function overlaps(a: Box, b: Box): boolean {
  return (
    a.left < b.left + b.width &&
    b.left < a.left + a.width &&
    a.top < b.top + b.height &&
    b.top < a.top + a.height
  );
}

function placeTooltip(anchor: ChartTooltipAnchor, box: SizedBox = WIDE_HOST): HTMLElement {
  const mounted = mount(
    <ChartTooltip label="September 2026 · UTC" value="43" anchor={anchor} />,
    box,
  );
  return mustFind(mounted.host, ".chart-tooltip");
}

describe("ChartTooltip", () => {
  it("renders the label, the value and its unit in one readout", () => {
    const mounted = mount(
      <ChartTooltip
        label="September 2026 · UTC"
        value="2.15%"
        unit="EPSS probability"
        anchor={{ x: 100, y: 40, width: 10, height: 20 }}
      />,
    );
    const tooltip = mustFind(mounted.host, ".chart-tooltip");
    expect(mustFind(tooltip, ".tt-label").textContent).toBe("September 2026 · UTC");
    const value = mustFind(tooltip, ".tt-value");
    expect(value.textContent).toBe("2.15%EPSS probability");
    // The unit is a quieter inline span, never a second line with its own label.
    const unit = mustFind(value, "span");
    expect(unit.textContent).toBe("EPSS probability");
    expect(unit.style.fontSize).toBe("0.65em");
  });

  it("omits the unit line entirely when the value carries it", () => {
    const mounted = mount(<ChartTooltip label="2026-09" value="43" anchor={{ x: 0, y: 0 }} />);
    const value = mustFind(mustFind(mounted.host, ".chart-tooltip"), ".tt-value");
    expect(value.textContent).toBe("43");
    expect(value.querySelector("span")).toBeNull();
  });

  it("truncates context to two facts even when the caller passes more", () => {
    const mounted = mount(
      <ChartTooltip
        label="September 2026 · UTC"
        value="43"
        unit="KEV additions"
        context={[
          "18.4% of the 234 catalog additions",
          "window maximum",
          "a third fact nobody sees",
        ]}
        anchor={{ x: 0, y: 0 }}
      />,
    );
    const tooltip = mustFind(mounted.host, ".chart-tooltip");
    const facts = Array.from(tooltip.querySelectorAll(".tt-share")).map((node) => node.textContent);
    expect(facts).toEqual(["18.4% of the 234 catalog additions", "window maximum"]);
    expect(facts).toHaveLength(2);
    expect(tooltip.textContent).not.toContain("a third fact nobody sees");
  });

  it("is a visual echo only: the mark's aria-label is what assistive tech reads", () => {
    const tooltip = placeTooltip({ x: 0, y: 0 });
    expect(tooltip.getAttribute("aria-hidden")).toBe("true");
  });

  it("derives its position from the anchor, clearing the mark by 12px", () => {
    const anchor = { x: 500, y: 40, width: 10, height: 20 };
    const box = tooltipBox(placeTooltip(anchor));
    // Left of the 70% flip point: the tooltip sits to the mark's right.
    expect(box.left).toBe(anchor.x + anchor.width + GAP);
    expect(box.left - (anchor.x + anchor.width)).toBe(GAP);
    // The top edge follows the mark, so the readout reads as attached to it.
    expect(box.top).toBe(anchor.y);
  });

  it("clamps the top edge inside the host instead of overflowing it", () => {
    const box = tooltipBox(placeTooltip({ x: 100, y: 280, width: 10, height: 20 }));
    expect(box.top).toBe(WIDE_HOST.height - TOOLTIP_HEIGHT - EDGE);
    expect(box.top + box.height).toBeLessThanOrEqual(WIDE_HOST.height - EDGE);
  });

  it("flips to the mark's left past 70% of the host width", () => {
    // Both sides fit at x=580 on an 800px host (the right candidate would land at
    // 602, inside the 612 clamp), so only the 70% rule can explain the left edge.
    const flipped = { x: 580, y: 40, width: 10, height: 20 };
    const rightCandidate = flipped.x + flipped.width + GAP;
    const leftCandidate = flipped.x - TOOLTIP_WIDTH - GAP;
    expect(rightCandidate).toBeLessThanOrEqual(WIDE_HOST.width - TOOLTIP_WIDTH - EDGE);
    expect(flipped.x + flipped.width / 2).toBeGreaterThan(WIDE_HOST.width * 0.7);

    const box = tooltipBox(placeTooltip(flipped));
    expect(box.left).toBe(leftCandidate);
    expect(box.left).not.toBe(rightCandidate);
    // And it still clears the mark, on the other side this time.
    expect(flipped.x - (box.left + box.width)).toBe(GAP);

    // One pixel below the threshold the same mark keeps the right-hand side.
    const before = { ...flipped, x: 555 };
    expect(before.x + before.width / 2).toBe(WIDE_HOST.width * 0.7);
    expect(tooltipBox(placeTooltip(before)).left).toBe(before.x + before.width + GAP);
  });

  it("never sits over its own mark, wherever the mark is", () => {
    const anchor = { x: 0, y: 40, width: 10, height: 20 };
    for (const x of [0, 40, 200, 400, 555, 560, 580, 700, 795]) {
      const candidate = { ...anchor, x };
      const box = tooltipBox(placeTooltip(candidate));
      expect(overlaps(box, markBox(candidate)), `mark at x=${x} is covered`).toBe(false);
      expect(box.left).toBeGreaterThanOrEqual(EDGE);
      expect(box.left + box.width).toBeLessThanOrEqual(WIDE_HOST.width - EDGE);
    }
  });

  it("clears a mark wider than its host vertically instead", () => {
    // A mark wider than the host leaves no room on either side; the fallback
    // moves the tooltip above or below it, still with the same 12px clearance.
    const narrowHost = { width: 100, height: 300 };
    const anchor = { x: 10, y: 20, width: 200, height: 10 };
    const box = tooltipBox(placeTooltip(anchor, narrowHost));
    expect(box.top).toBe(anchor.y + anchor.height + GAP);
    expect(box.top - (anchor.y + anchor.height)).toBe(GAP);
    expect(overlaps(box, markBox(anchor))).toBe(false);
  });
});

interface MonthRow {
  month: string;
  count: number;
}

const MONTHS: readonly MonthRow[] = [
  { month: "2026-01", count: 12 },
  { month: "2026-02", count: 0 },
];

const MONTH_COLUMNS: readonly ChartTableColumn<MonthRow>[] = [
  { key: "month", header: "Month (UTC)", value: (row) => row.month },
  { key: "count", header: "Additions", value: (row) => String(row.count) },
];

function renderMonthsTable(rows: readonly MonthRow[]): string {
  return renderToStaticMarkup(
    <ChartTable
      caption="KEV catalog additions by UTC month"
      columns={MONTH_COLUMNS}
      rows={rows}
      rowKey={(row) => row.month}
    />,
  );
}

describe("ChartTable", () => {
  it("is a native disclosure, collapsed by default and needing no JavaScript", () => {
    const markup = renderMonthsTable(MONTHS);
    expect(markup).toContain('<details class="chart-table"');
    // No `open` attribute: the values are in the payload but not on screen until
    // the reader opens them, which is what keeps hover from being load-bearing.
    expect(markup).not.toMatch(/<details[^>]*\bopen\b/);
    expect(markup).toContain("<summary>Data table</summary>");

    const mounted = mount(
      <ChartTable caption="c" columns={MONTH_COLUMNS} rows={MONTHS} rowKey={(row) => row.month} />,
    );
    const details = mustFind(mounted.host, "details");
    expect((details as HTMLDetailsElement).open).toBe(false);
  });

  it("labels every column and every row, and names itself to a screen reader", () => {
    const markup = renderMonthsTable(MONTHS);
    expect(markup).toContain(
      '<caption class="sr-only">KEV catalog additions by UTC month</caption>',
    );
    expect(markup).toContain('<th scope="col">Month (UTC)</th>');
    expect(markup).toContain('<th scope="col">Additions</th>');
    // The first column is the row header by default, so a cell is never unlabeled.
    expect(markup).toContain('<th scope="row">2026-01</th>');
    expect(markup).toContain("<td>12</td>");
  });

  it("states absence in words instead of rendering an empty tbody", () => {
    const markup = renderToStaticMarkup(
      <ChartTable
        caption="Observations"
        columns={MONTH_COLUMNS}
        rows={[]}
        emptyMessage="No observation in this window."
        rowKey={(row: MonthRow) => row.month}
      />,
    );
    expect(markup).toContain("No observation in this window.");
    // One row, spanning every column: never a header row over nothing, and never
    // a fabricated zero where a value is unknown. (`colSpan` is emitted verbatim
    // by React 19's server renderer, so the attribute name is matched loosely.)
    expect(markup).toMatch(/<td colspan="2">No observation in this window\.<\/td>/i);
    expect(markup.match(/<tr>/g) ?? []).toHaveLength(2);
    expect(markup).not.toContain(">0<");
  });

  it("keys rows by their identity, not by their position", () => {
    const mounted = mount(
      <ChartTable caption="c" columns={MONTH_COLUMNS} rows={MONTHS} rowKey={(row) => row.month} />,
    );
    const rowsBefore = Array.from(mounted.host.querySelectorAll("tbody tr"));
    const january = rowsBefore[0] as HTMLElement;
    expect(january.textContent).toContain("2026-01");

    // Same rows, new order and a new array identity: a positional key would reuse
    // the first slot for February and rewrite January's node in place.
    mounted.rerender(
      <ChartTable
        caption="c"
        columns={MONTH_COLUMNS}
        rows={[...MONTHS].reverse()}
        rowKey={(row) => row.month}
      />,
    );
    const rowsAfter = Array.from(mounted.host.querySelectorAll("tbody tr"));
    expect(rowsAfter[1]).toBe(january);
    expect(january.textContent).toContain("2026-01");
  });
});

interface RovingHarnessProps {
  count: number;
  initialIndex?: number;
  orientation?: RovingOrientation;
  onDismiss?: () => void;
}

function RovingHarness({ count, initialIndex, orientation, onDismiss }: RovingHarnessProps) {
  const roving = useRovingMarkFocus({ count, initialIndex, orientation, onDismiss });
  return (
    <div role="group" aria-label="marks">
      {Array.from({ length: count }, (_, index) => (
        <div
          key={index}
          role="img"
          data-mark={index}
          aria-label={`mark ${index}`}
          ref={roving.registerMark(index)}
          {...roving.markProps(index)}
        />
      ))}
    </div>
  );
}

function mountRoving(props: RovingHarnessProps): HTMLElement[] {
  const mounted = mount(<RovingHarness {...props} />);
  return Array.from(mounted.host.querySelectorAll<HTMLElement>("[data-mark]"));
}

function press(mark: Element, key: string): void {
  act(() => {
    mark.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
  });
}

function tabStops(marks: readonly HTMLElement[]): number[] {
  return marks
    .filter((mark) => mark.getAttribute("tabindex") === "0")
    .map((mark) => Number(mark.dataset.mark));
}

describe("useRovingMarkFocus", () => {
  it("exposes the group as exactly one Tab stop", () => {
    const marks = mountRoving({ count: 5, initialIndex: 4 });
    expect(tabStops(marks)).toEqual([4]);
    expect(marks.map((mark) => mark.getAttribute("tabindex"))).toEqual([
      "-1",
      "-1",
      "-1",
      "-1",
      "0",
    ]);
  });

  it("steps with the arrow keys and moves real focus with the mark", () => {
    const marks = mountRoving({ count: 5, initialIndex: 0 });
    press(marks[0] as HTMLElement, "ArrowRight");
    expect(document.activeElement).toBe(marks[1]);
    expect(tabStops(marks)).toEqual([1]);

    press(marks[1] as HTMLElement, "ArrowLeft");
    expect(document.activeElement).toBe(marks[0]);
    expect(tabStops(marks)).toEqual([0]);
  });

  it("wraps at both ends, so the first ArrowRight after entry is never a no-op", () => {
    // Every chart enters on its latest mark (the data-visibility default), which
    // is why a clamped step made the first keypress after entering do nothing.
    const marks = mountRoving({ count: 5, initialIndex: 4 });
    press(marks[4] as HTMLElement, "ArrowRight");
    expect(document.activeElement).toBe(marks[0]);
    expect(tabStops(marks)).toEqual([0]);

    press(marks[0] as HTMLElement, "ArrowLeft");
    expect(document.activeElement).toBe(marks[4]);
    expect(tabStops(marks)).toEqual([4]);
  });

  it("keeps Home and End absolute rather than wrapping", () => {
    const marks = mountRoving({ count: 5, initialIndex: 2 });
    press(marks[2] as HTMLElement, "End");
    expect(document.activeElement).toBe(marks[4]);
    press(marks[4] as HTMLElement, "Home");
    expect(document.activeElement).toBe(marks[0]);
  });

  it("reads the arrow axis from the orientation", () => {
    const marks = mountRoving({ count: 3, initialIndex: 0, orientation: "vertical" });
    press(marks[0] as HTMLElement, "ArrowDown");
    expect(document.activeElement).toBe(marks[1]);
    press(marks[0] as HTMLElement, "ArrowUp");
    expect(document.activeElement).toBe(marks[2]);
  });

  it("hands Escape to the surface without moving the mark", () => {
    const onDismiss = vi.fn();
    const marks = mountRoving({ count: 3, initialIndex: 1, onDismiss });
    press(marks[1] as HTMLElement, "Escape");
    expect(onDismiss).toHaveBeenCalledTimes(1);
    expect(tabStops(marks)).toEqual([1]);
  });

  it("ignores keys that are not steps", () => {
    const onDismiss = vi.fn();
    const marks = mountRoving({ count: 3, initialIndex: 1, onDismiss });
    press(marks[1] as HTMLElement, "Tab");
    press(marks[1] as HTMLElement, "Enter");
    expect(tabStops(marks)).toEqual([1]);
    expect(onDismiss).not.toHaveBeenCalled();
  });
});

interface Mark {
  key: string;
  anchor: ChartTooltipAnchor;
}

const MARK_A: Mark = { key: "a", anchor: { x: 0, y: 0 } };
const MARK_B: Mark = { key: "b", anchor: { x: 40, y: 0 } };

let slots: HoverFocusMarks<Mark> | null = null;

function SlotHarness() {
  const marks = useHoverFocusMarks<Mark>();
  slots = marks;
  return <span data-testid="active">{marks.active?.key ?? "none"}</span>;
}

function mountSlots(): { active: () => string; slots: () => HoverFocusMarks<Mark> } {
  const mounted = mount(<SlotHarness />);
  const read = () => mustFind(mounted.host, '[data-testid="active"]').textContent ?? "none";
  const readSlots = () => {
    if (slots === null) throw new Error("slot harness did not render");
    return slots;
  };
  return { active: read, slots: readSlots };
}

describe("useHoverFocusMarks", () => {
  it("lets the pointer leave without blanking what the keyboard focused", () => {
    const { active, slots: read } = mountSlots();
    act(() => read().setFocus(MARK_A));
    expect(active()).toBe("a");
    act(() => read().setHover(MARK_B));
    expect(active()).toBe("b");
    // hover ?? focus: clearing the pointer's slot restores the focused reading
    // instead of closing the tooltip the reader navigated to.
    act(() => read().clearHover());
    expect(active()).toBe("a");
  });

  it("keeps the pointer's reading when focus leaves while hovering", () => {
    const { active, slots: read } = mountSlots();
    act(() => read().setFocus(MARK_A));
    act(() => read().setHover(MARK_B));
    act(() => read().clearFocus());
    expect(active()).toBe("b");
    act(() => read().clearHover());
    expect(active()).toBe("none");
  });

  it("is empty when neither input has a mark", () => {
    const { active } = mountSlots();
    expect(active()).toBe("none");
  });
});

describe("anchorFromElement", () => {
  function mockRect(el: Element, left: number, top: number, width: number, height: number): void {
    vi.spyOn(el, "getBoundingClientRect").mockReturnValue(new DOMRect(left, top, width, height));
  }

  it("measures the mark inside the host's coordinate space", () => {
    const host = document.createElement("div");
    const mark = document.createElement("div");
    host.append(mark);
    mockRect(host, 100, 40, 400, 300);
    mockRect(mark, 120, 60, 10, 20);

    expect(anchorFromElement(mark, host)).toEqual({ x: 20, y: 20, width: 10, height: 20 });
  });

  it("is scroll-invariant: moving both boxes leaves the anchor unchanged", () => {
    const host = document.createElement("div");
    const mark = document.createElement("div");
    host.append(mark);
    mockRect(host, 137, 91, 400, 300);
    mockRect(mark, 157, 111, 10, 20);

    // Same mark, same host, page scrolled 37/51px: the tooltip must not move.
    expect(anchorFromElement(mark, host)).toEqual({ x: 20, y: 20, width: 10, height: 20 });
  });

  it("returns the host origin when there is no host to measure against", () => {
    const mark = document.createElement("div");
    mockRect(mark, 120, 60, 10, 20);
    expect(anchorFromElement(mark, null)).toEqual({ x: 0, y: 0 });
  });
});
