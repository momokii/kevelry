"use client";

import { useCallback, useState } from "react";

import type { ChartTooltipAnchor } from "./ChartTooltip";

/** A mark the tooltip can describe: its identity plus where the tooltip goes. */
export interface HoverFocusMark {
  anchor: ChartTooltipAnchor;
}

export interface HoverFocusMarks<Mark extends HoverFocusMark> {
  /** The mark to read: the pointer's mark while it is over one, otherwise the keyboard's. */
  active: Mark | null;
  setHover: (mark: Mark) => void;
  clearHover: () => void;
  setFocus: (mark: Mark) => void;
  clearFocus: () => void;
}

/**
 * The one hover/focus slot pair. Two slots are written and one is read
 * (`active = hover ?? focus`), which is what makes the invariant hold: clearing
 * the pointer's slot can never blank a reading the keyboard still has focus on,
 * so a mouse leaving the plot cannot erase a tooltip the reader navigated to.
 * The reverse is not true — a pointer mark wins over a focused one, because the
 * pointer is the later intent.
 *
 * Both slots hold the same shape, so a consumer renders one tooltip from
 * `active` with one set of strings, whichever input produced it.
 */
export function useHoverFocusMarks<Mark extends HoverFocusMark>(): HoverFocusMarks<Mark> {
  const [hover, setHoverMark] = useState<Mark | null>(null);
  const [focus, setFocusMark] = useState<Mark | null>(null);

  const setHover = useCallback((mark: Mark) => setHoverMark(mark), []);
  const clearHover = useCallback(() => setHoverMark(null), []);
  const setFocus = useCallback((mark: Mark) => setFocusMark(mark), []);
  const clearFocus = useCallback(() => setFocusMark(null), []);

  return { active: hover ?? focus, setHover, clearHover, setFocus, clearFocus };
}
