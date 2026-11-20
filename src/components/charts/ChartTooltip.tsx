"use client";

import { useLayoutEffect, useRef, useState } from "react";

/** Keep the tooltip off the host's own border. */
const EDGE = 8;
/** Clearance between the mark and the tooltip, so the mark is never covered. */
const GAP = 12;
/** Past this fraction of the host width the tooltip flips to the left. */
const FLIP_AT = 0.7;

export interface ChartTooltipAnchor {
  /** Left edge of the mark, in the host's coordinate space. */
  x: number;
  /** Top edge of the mark, in the host's coordinate space. */
  y: number;
  width?: number;
  height?: number;
}

export interface ChartTooltipProps {
  /** The mark's period or identity, with its date basis: `September 2026 · UTC`. */
  label: string;
  /** The exact number, already formatted: `43`, `2.15%`. */
  value: string;
  /** The value's unit, rendered inside the value line: `KEV additions`. */
  unit?: string;
  /** At most two supporting facts; each names its denominator. Anything past the second is dropped. */
  context?: readonly string[];
  /** The mark's rect inside a `position: relative` host (`.chart-frame` or the mark's wrapper). */
  anchor: ChartTooltipAnchor;
  testId?: string;
}

interface Placement {
  left: number;
  top: number;
}

/**
 * The only way a chart converts a mark's on-screen rect into the anchor the
 * tooltip places against: `markEl`'s box measured inside `hostEl`'s box, which is
 * the `position: relative` host the tooltip is a child of. Every mark-anchored
 * tooltip in the app calls this instead of repeating the two `getBoundingClientRect`
 * calls, so a mark that moves (resize, scroll, a bucket switch) reads the same way
 * everywhere.
 */
export function anchorFromElement(mark: Element, host: Element | null): ChartTooltipAnchor {
  if (host === null) return { x: 0, y: 0 };
  const rect = mark.getBoundingClientRect();
  const box = host.getBoundingClientRect();
  return {
    x: rect.left - box.left,
    y: rect.top - box.top,
    width: rect.width,
    height: rect.height,
  };
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

function placeInsideHost(node: HTMLElement, anchor: ChartTooltipAnchor): Placement {
  const host = (node.offsetParent as HTMLElement | null) ?? node.parentElement;
  if (host === null) return { left: EDGE, top: EDGE };

  const width = node.offsetWidth;
  const height = node.offsetHeight;
  const maxLeft = Math.max(EDGE, host.clientWidth - width - EDGE);
  const maxTop = Math.max(EDGE, host.clientHeight - height - EDGE);

  const anchorWidth = anchor.width ?? 0;
  const anchorHeight = anchor.height ?? 0;
  const right = anchor.x + anchorWidth + GAP;
  const left = anchor.x - width - GAP;
  // In the last 30% of the host the tooltip prefers the mark's left side.
  const preferLeft = anchor.x + anchorWidth / 2 > host.clientWidth * FLIP_AT;
  const beside = (preferLeft ? [left, right] : [right, left]).filter(
    (candidate) => candidate >= EDGE && candidate <= maxLeft,
  );
  const first = beside[0];

  if (first !== undefined) {
    // Sitting beside the mark means the tooltip can never cover it, whatever its height.
    return { left: first, top: clamp(anchor.y, EDGE, maxTop) };
  }

  // A mark wider than the host leaves no room on either side: clear it vertically instead.
  const above = anchor.y - height - GAP;
  const below = anchor.y + anchorHeight + GAP;
  const top = above >= EDGE || below > maxTop ? above : below;
  return { left: clamp(anchor.x, EDGE, maxLeft), top: clamp(top, EDGE, maxTop) };
}

/**
 * The one tooltip renderer for every chart. It reuses the shared `.chart-tooltip`
 * styling, so it cannot drift from the tooltips already on the page: no new
 * colour, no new animation, no transition beyond what the stylesheet already has.
 *
 * It is a visual echo only (`aria-hidden`): the mark's own `aria-label` names the
 * value for assistive tech, and the `ChartTable` below the chart carries every
 * value without a pointer. Neither depends on this element existing.
 */
export function ChartTooltip({
  label,
  value,
  unit,
  context = [],
  anchor,
  testId,
}: ChartTooltipProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const [placement, setPlacement] = useState<Placement>({ left: EDGE, top: EDGE });
  const facts = context.slice(0, 2);
  const { x, y, width = 0, height = 0 } = anchor;

  useLayoutEffect(() => {
    const node = ref.current;
    if (node === null) return;
    setPlacement(placeInsideHost(node, { x, y, width, height }));
  }, [x, y, width, height, label, value, unit, facts.join("\u0000")]);

  return (
    <div
      ref={ref}
      className="chart-tooltip"
      style={{ left: placement.left, top: placement.top }}
      data-testid={testId}
      aria-hidden="true"
    >
      <div className="tt-label">{label}</div>
      <div className="tt-value">
        {value}
        {unit === undefined ? null : (
          <span style={{ fontSize: "0.65em", fontWeight: 500, marginLeft: "0.28em" }}>{unit}</span>
        )}
      </div>
      {facts.map((fact) => (
        <div key={fact} className="tt-share">
          {fact}
        </div>
      ))}
    </div>
  );
}
