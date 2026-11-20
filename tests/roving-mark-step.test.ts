// The sparkline and the KEV rhythm both enter on their latest mark, so a clamped
// ArrowRight made the first keypress after entering a no-op. The step now wraps:
// Right on the last mark goes to the first, Left on the first goes to the last.
// Home and End stay absolute (they name an end, they do not step from one).

import { describe, expect, it } from "vitest";

import { steppedIndex } from "../src/components/charts/useRovingMarkFocus";

describe("roving mark stepping", () => {
  it("changes the active mark on the first ArrowRight after entering at the latest", () => {
    // `initialIndex` is the latest mark for every chart that uses this hook.
    expect(steppedIndex("ArrowRight", 11, 12, "horizontal")).toBe(0);
    expect(steppedIndex("ArrowRight", 44, 45, "horizontal")).toBe(0);
    expect(steppedIndex("ArrowRight", 1, 2, "horizontal")).toBe(0);
  });

  it("wraps backwards from the first mark to the latest", () => {
    expect(steppedIndex("ArrowLeft", 0, 12, "horizontal")).toBe(11);
  });

  it("steps normally between the ends, in both directions", () => {
    expect(steppedIndex("ArrowRight", 0, 12, "horizontal")).toBe(1);
    expect(steppedIndex("ArrowLeft", 11, 12, "horizontal")).toBe(10);
    expect(steppedIndex("ArrowDown", 0, 3, "vertical")).toBe(1);
    expect(steppedIndex("ArrowUp", 0, 3, "vertical")).toBe(2);
  });

  it("keeps Home and End absolute instead of wrapping", () => {
    expect(steppedIndex("Home", 11, 12, "horizontal")).toBe(0);
    expect(steppedIndex("End", 0, 12, "horizontal")).toBe(11);
    expect(steppedIndex("End", 11, 12, "horizontal")).toBe(11);
    expect(steppedIndex("Home", 0, 12, "horizontal")).toBe(0);
  });

  it("ignores keys that are not steps", () => {
    expect(steppedIndex("Enter", 3, 12, "horizontal")).toBeNull();
    expect(steppedIndex("ArrowDown", 3, 12, "horizontal")).toBeNull();
    expect(steppedIndex("ArrowRight", 0, 1, "horizontal")).toBe(0);
  });
});
