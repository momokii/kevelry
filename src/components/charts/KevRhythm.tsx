"use client";

import { useEffect, useRef, useState } from "react";

import { ChartTable } from "./ChartTable";
import { ChartTooltip, type ChartTooltipAnchor } from "./ChartTooltip";
import { formatInt, monthLong, monthShort } from "./chartTokens";
import { useRovingMarkFocus } from "./useRovingMarkFocus";

/** One decimal place (`13.4%`). The window total is the denominator: the same
 * number the caption prints and the data table sums to. */
function shareOneDecimal(count: number, total: number): string {
  if (total <= 0) return "0.0%";
  return `${((count / total) * 100).toFixed(1)}%`;
}

/** The reading for one month, identical for pointer and keyboard. */
function monthFacts(entry: { count: number }, total: number, isHigh: boolean): string[] {
  const facts = [
    `${formatInt(entry.count)} of ${formatInt(total)} additions, ${shareOneDecimal(entry.count, total)}`,
  ];
  if (isHigh) facts.push("window maximum");
  return facts.slice(0, 2);
}

function monthLabel(
  entry: { month: string; count: number },
  total: number,
  isHigh: boolean,
): string {
  const share = shareOneDecimal(entry.count, total);
  return `${monthLong(entry.month)} · UTC: ${formatInt(entry.count)} KEV additions, ${share} of the ${formatInt(total)} in this window${isHigh ? ", window maximum" : ""}.`;
}

/**
 * KEV additions per UTC month, as twelve mini bars.
 *
 * Every bar — including a month with no additions — is a mark: hover and focus
 * produce the same tooltip, the keyboard is one Tab stop with Arrow/Home/End
 * roving between all twelve, and a zero month keeps a 1px bar inside a
 * full-height hit target instead of disappearing. Nothing here is decorative:
 * the only emphasis is the mark under the pointer or the keyboard, plus the
 * window maximum, which the panel's "How to read" line names. Every value also
 * exists without hover: the caption prints the window total and the disclosure
 * lists all twelve months.
 *
 * Touch is first class: a tap pins the tooltip and it stays after the finger
 * lifts, because a touch pointer leaves the bar on lift and clearing there is
 * exactly what erased the readout. The pin survives until another tap (which
 * moves it, or closes it when it lands on the same bar) or a tap outside the
 * chart. Mouse hover still clears on leave.
 */
export function KevRhythm({
  months,
  total,
}: {
  months: Array<{ month: string; count: number }>;
  total: number;
}) {
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [focusIndex, setFocusIndex] = useState<number | null>(null);
  const [touchPinned, setTouchPinned] = useState(false);
  const [anchor, setAnchor] = useState<ChartTooltipAnchor>({ x: 0, y: 0 });
  const hostRef = useRef<HTMLDivElement | null>(null);

  // A pinned touch readout is dismissed by the next tap outside the chart, which
  // is the only way touch can express "look away". Inert while nothing is pinned.
  useEffect(() => {
    if (!touchPinned) return;
    const dismissOutside = (event: PointerEvent) => {
      if (event.pointerType !== "touch") return;
      const host = hostRef.current;
      if (host !== null && event.target instanceof Node && host.contains(event.target)) return;
      setHoverIndex(null);
      setTouchPinned(false);
    };
    document.addEventListener("pointerdown", dismissOutside, true);
    return () => document.removeEventListener("pointerdown", dismissOutside, true);
  }, [touchPinned]);

  const scaleMax = Math.max(1, ...months.map((entry) => entry.count));
  const peak = months.reduce<{ month: string; count: number } | null>(
    (best, entry) => (best === null || entry.count > best.count ? entry : best),
    null,
  );
  const roving = useRovingMarkFocus({
    count: months.length,
    initialIndex: Math.max(0, months.length - 1),
    // Escape clears the readout but keeps focus on the bar, so the next arrow
    // picks up where the reader was instead of dropping out of the chart.
    onDismiss: () => {
      setHoverIndex(null);
      setFocusIndex(null);
    },
  });
  const tipIndex = hoverIndex ?? focusIndex;
  const tipEntry = tipIndex === null ? undefined : months[tipIndex];

  const anchorFor = (node: HTMLElement): ChartTooltipAnchor => {
    const host = hostRef.current;
    if (host === null) return { x: 0, y: 0 };
    const bar = node.getBoundingClientRect();
    const box = host.getBoundingClientRect();
    return {
      x: bar.left - box.left,
      y: bar.top - box.top,
      width: bar.width,
      height: bar.height,
    };
  };

  return (
    <div className="chart-frame" ref={hostRef} data-testid="overview-kev-chart">
      {tipEntry === undefined ? null : (
        <ChartTooltip
          label={`${monthLong(tipEntry.month)} · UTC`}
          value={formatInt(tipEntry.count)}
          unit="additions"
          context={monthFacts(tipEntry, total, tipEntry.count === peak?.count)}
          anchor={anchor}
          testId="overview-kev-tooltip"
        />
      )}
      <div
        className="kev-bars"
        role="group"
        aria-label={`KEV catalog additions by UTC month: ${months.length} months, ${formatInt(total)} additions${peak === null ? "" : `, window maximum ${formatInt(peak.count)} in ${monthLong(peak.month)}`}.`}
        onPointerLeave={(event) => {
          // A touch pointer leaves the bar when the finger lifts; clearing there
          // is what made a tap flash the tooltip and lose it. Mouse still clears.
          if (event.pointerType !== "touch") setHoverIndex(null);
        }}
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
            setFocusIndex(null);
          }
        }}
      >
        {months.map((entry, index) => {
          const isHigh = entry.count === peak?.count;
          return (
            <div
              key={entry.month}
              className="kev-bar"
              role="img"
              data-index={index}
              data-testid={`overview-kev-bar-${entry.month}`}
              data-zero={entry.count === 0 ? "true" : undefined}
              data-window-high={isHigh ? "true" : undefined}
              aria-label={monthLabel(entry, total, isHigh)}
              tabIndex={index === roving.activeIndex ? 0 : -1}
              ref={roving.registerMark(index)}
              onFocus={(event) => {
                roving.setActiveIndex(index);
                // A touch tap focuses the bar too (it is a tab stop), but it is
                // not a request to read the bar with the keyboard: the pin owns
                // the readout, and a focus index alive in parallel would keep the
                // tooltip open after the second tap that should close it.
                if (!event.currentTarget.matches(":focus-visible")) {
                  setFocusIndex(null);
                  return;
                }
                setFocusIndex(index);
                setAnchor(anchorFor(event.currentTarget));
              }}
              onPointerEnter={(event) => {
                // Touch is handled by pointerdown (tap = pin); pointerenter also
                // fires on the way down and would fight the pin toggle.
                if (event.pointerType === "touch") return;
                setHoverIndex(index);
                setAnchor(anchorFor(event.currentTarget));
              }}
              onPointerDown={(event) => {
                if (event.pointerType !== "touch") return;
                // The tap's own focus event follows this handler; keep the
                // keyboard readout out of it.
                setFocusIndex(null);
                // Tap = pin. A second tap on the pinned bar closes it; a tap on
                // another bar moves the pin there.
                if (touchPinned && hoverIndex === index) {
                  setHoverIndex(null);
                  setTouchPinned(false);
                  return;
                }
                setAnchor(anchorFor(event.currentTarget));
                setHoverIndex(index);
                setTouchPinned(true);
              }}
              onKeyDown={roving.markProps(index).onKeyDown}
            >
              <span
                className="kev-bar-fill"
                style={{
                  // A zero month is a real value: 1px mark, full-height target.
                  height: entry.count === 0 ? "1px" : `${6 + (entry.count / scaleMax) * 78}px`,
                }}
                aria-hidden="true"
              />
              <span className="kev-bar-label" aria-hidden="true">
                {monthShort(entry.month)}
              </span>
            </div>
          );
        })}
      </div>
      <p className="chart-note">
        <strong>{formatInt(total)}</strong> catalog additions in twelve months. This is catalog
        activity, not exploitation volume: a quiet month means no new listings.
      </p>
      <ChartTable
        caption="KEV catalog additions by UTC month"
        summary="All months"
        testId="overview-kev-table"
        rows={months}
        rowKey={(entry) => entry.month}
        columns={[
          {
            key: "month",
            header: "Month (UTC)",
            value: (entry) => monthLong(entry.month),
          },
          {
            key: "additions",
            header: "Additions",
            value: (entry) => formatInt(entry.count),
          },
          {
            key: "share",
            header: "Share of window",
            value: (entry) => shareOneDecimal(entry.count, total),
          },
        ]}
      />
    </div>
  );
}
