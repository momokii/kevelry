"use client";

import { useCallback, useRef, useState } from "react";
import type { KeyboardEvent, RefCallback } from "react";

export type RovingOrientation = "horizontal" | "vertical";

export interface RovingMarkOptions {
  /** How many marks the group holds. */
  count: number;
  /** Which mark is the single Tab stop before anyone interacts. Defaults to the first. */
  initialIndex?: number;
  /** Arrow axis. Horizontal reads left/right, vertical reads up/down. Defaults to horizontal. */
  orientation?: RovingOrientation;
  /**
   * Name of the mark at `index`, for the polite live region. Omit it when the
   * focused element is a control whose own `aria-label` already carries the value
   * (a `<button>` hit target, a link): moving focus announces it, and a live
   * region on top would say everything twice.
   */
  describe?: (index: number) => string;
  /** Fires whenever the active mark changes, by focus or by keyboard. */
  onActiveChange?: (index: number) => void;
  /** Escape, so the surface can clear its own active or pinned state. */
  onDismiss?: () => void;
}

export interface RovingMarkHandlers {
  tabIndex: 0 | -1;
  onFocus: () => void;
  onKeyDown: (event: KeyboardEvent<HTMLElement>) => void;
}

export interface RovingMarks {
  activeIndex: number;
  setActiveIndex: (index: number) => void;
  /** Move the active mark and put real DOM focus on it. */
  focusMark: (index: number) => void;
  markProps: (index: number) => RovingMarkHandlers;
  /** Ref callback for a mark at `index`, used by `focusMark`. */
  registerMark: (index: number) => RefCallback<HTMLElement>;
  /** `describe(activeIndex)` when `describe` is provided, otherwise empty. */
  announcement: string;
}

function clampIndex(index: number, count: number): number {
  if (count <= 0) return 0;
  return Math.min(Math.max(index, 0), count - 1);
}

function steppedIndex(
  key: string,
  index: number,
  count: number,
  orientation: RovingOrientation,
): number | null {
  const last = Math.max(0, count - 1);
  if (key === (orientation === "vertical" ? "ArrowDown" : "ArrowRight")) {
    return Math.min(last, index + 1);
  }
  if (key === (orientation === "vertical" ? "ArrowUp" : "ArrowLeft")) {
    return Math.max(0, index - 1);
  }
  if (key === "Home") return 0;
  if (key === "End") return last;
  return null;
}

/**
 * The keyboard contract for a dense chart: the group of marks is one Tab stop,
 * Arrow/Home/End move between marks, and the active mark is clamped (never
 * wrapping, so End on the last mark stays put instead of jumping home).
 *
 * Focus moves to the real mark node rather than staying on a container, which is
 * what `DensityMatrix` already does: the focused element's own `aria-label` is the
 * announcement, so nothing is said twice. Surfaces that cannot name the focused
 * node pass `describe` and render `announcement` in an `aria-live="polite"`
 * region, which is how the sparkline will announce the point it landed on.
 */
export function useRovingMarkFocus({
  count,
  initialIndex = 0,
  orientation = "horizontal",
  describe,
  onActiveChange,
  onDismiss,
}: RovingMarkOptions): RovingMarks {
  const [active, setActive] = useState(() => clampIndex(initialIndex, count));
  const nodes = useRef(new Map<number, HTMLElement>());
  const activeIndex = clampIndex(active, count);

  const setActiveIndex = useCallback(
    (index: number) => {
      const next = clampIndex(index, count);
      setActive(next);
      onActiveChange?.(next);
    },
    [count, onActiveChange],
  );

  const focusMark = useCallback(
    (index: number) => {
      const next = clampIndex(index, count);
      setActiveIndex(next);
      nodes.current.get(next)?.focus();
    },
    [count, setActiveIndex],
  );

  const registerMark = useCallback((index: number): RefCallback<HTMLElement> => {
    return (node) => {
      if (node === null) nodes.current.delete(index);
      else nodes.current.set(index, node);
    };
  }, []);

  const markProps = (index: number): RovingMarkHandlers => ({
    tabIndex: index === activeIndex ? 0 : -1,
    onFocus: () => {
      if (index !== activeIndex) setActiveIndex(index);
    },
    onKeyDown: (event) => {
      if (event.key === "Escape") {
        onDismiss?.();
        return;
      }
      const next = steppedIndex(event.key, index, count, orientation);
      if (next === null) return;
      event.preventDefault();
      focusMark(next);
    },
  });

  const announcement = count > 0 && describe !== undefined ? describe(activeIndex) : "";

  return {
    activeIndex,
    setActiveIndex,
    focusMark,
    markProps,
    registerMark,
    announcement,
  };
}
