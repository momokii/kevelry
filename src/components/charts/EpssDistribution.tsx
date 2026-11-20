"use client";

import { useMemo, useRef } from "react";

import { AxisBottom, AxisLeft } from "@visx/axis";
import { GridRows } from "@visx/grid";
import { Group } from "@visx/group";
import { ParentSize } from "@visx/responsive";
import { scaleBand, scaleLog } from "@visx/scale";

import { ChartTooltip, anchorFromElement, type ChartTooltipAnchor } from "./ChartTooltip";
import { EPSS_LOG_BINS, formatCompact, formatInt, sharePercent } from "./chartTokens";
import { useHoverFocusMarks } from "./useHoverFocusMarks";

const MARGIN = { top: 18, right: 8, bottom: 28, left: 38 };
const HEIGHT = 196;

function EpssSvg({
  width,
  histogram,
  total,
}: {
  width: number;
  histogram: number[];
  total: number;
}) {
  // Hover and focus write separate slots and render the same strings, so the
  // pointer leaving the histogram cannot blank the bin the keyboard is on.
  const marks = useHoverFocusMarks<{ index: number; anchor: ChartTooltipAnchor }>();
  const hostRef = useRef<HTMLDivElement | null>(null);
  const innerWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const values = EPSS_LOG_BINS.map((_, index) => histogram[index] ?? 0);
  const max = Math.max(1, ...values);
  const xScale = useMemo(
    () =>
      scaleBand<string>({
        domain: EPSS_LOG_BINS.map((bin) => bin.label),
        range: [0, innerWidth],
        padding: 0.28,
      }),
    [innerWidth],
  );
  const yScale = useMemo(
    () =>
      scaleLog<number>({
        domain: [1, max],
        range: [innerHeight, 0],
        clamp: true,
      }),
    [innerHeight, max],
  );
  const activeIndex = marks.active?.index ?? null;
  const active =
    activeIndex === null
      ? null
      : { bin: EPSS_LOG_BINS[activeIndex], count: values[activeIndex] ?? 0 };
  const bandwidth = xScale.bandwidth();
  return (
    <div className="chart-frame" ref={hostRef} onMouseLeave={marks.clearHover}>
      {active !== null && activeIndex !== null && marks.active !== null ? (
        <ChartTooltip
          label={`EPSS ${active.bin?.label}`}
          value={formatInt(active.count)}
          context={[
            `${sharePercent(active.count, total)} of EPSS-scored records`,
            "Log-spaced probability buckets",
          ]}
          anchor={marks.active.anchor}
        />
      ) : null}
      <svg
        className="chart-svg"
        width={width}
        height={HEIGHT}
        viewBox={`0 0 ${width} ${HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="EPSS probability distribution across nine log-spaced buckets. Most records sit below ten percent."
      >
        <Group left={MARGIN.left} top={MARGIN.top}>
          <GridRows
            scale={yScale}
            width={innerWidth}
            height={innerHeight}
            numTicks={3}
            stroke="var(--ui-rule-soft)"
            strokeDasharray="3 4"
          />
          {EPSS_LOG_BINS.map((bin, index) => {
            const count = values[index] ?? 0;
            const barX = xScale(bin.label) ?? 0;
            const barY = count > 0 ? yScale(count) : innerHeight;
            const isActive = activeIndex === index;
            return (
              <rect
                key={bin.label}
                x={barX}
                y={barY}
                width={bandwidth}
                height={Math.max(1, innerHeight - barY)}
                rx={2}
                fill="var(--ui-ink)"
                fillOpacity={isActive ? 1 : index === 0 ? 0.9 : 0.55}
                role="img"
                tabIndex={0}
                aria-label={`EPSS ${bin.label}: ${formatInt(count)} records, ${sharePercent(count, total)} of scored.`}
                onMouseEnter={(event) =>
                  marks.setHover({
                    index,
                    anchor: anchorFromElement(event.currentTarget, hostRef.current),
                  })
                }
                onFocus={(event) =>
                  marks.setFocus({
                    index,
                    anchor: anchorFromElement(event.currentTarget, hostRef.current),
                  })
                }
                onBlur={marks.clearFocus}
              />
            );
          })}
          <AxisLeft
            scale={yScale}
            numTicks={3}
            tickFormat={(value) => formatCompact(Number(value))}
            tickLength={0}
            tickLabelProps={() => ({
              fill: "var(--ui-ink-3)",
              fontSize: 9.5,
              fontFamily: "var(--ui-font-mono)",
              dx: -5,
              dy: 3,
              textAnchor: "end",
            })}
            axisClassName="chart-axis"
            tickStroke="transparent"
          />
          <AxisBottom
            scale={xScale}
            top={innerHeight}
            tickValues={EPSS_LOG_BINS.filter((_, index) => index % 2 === 0).map((bin) => bin.label)}
            tickFormat={(value) => {
              const bin = EPSS_LOG_BINS.find((entry) => entry.label === String(value));
              return bin?.short ?? String(value);
            }}
            tickLength={3}
            tickLabelProps={() => ({
              fill: "var(--ui-ink-3)",
              fontSize: 7.5,
              fontFamily: "var(--ui-font-mono)",
              textAnchor: "middle",
              dy: 3,
            })}
            axisClassName="chart-axis"
            tickStroke="var(--ui-rule)"
          />
        </Group>
      </svg>
    </div>
  );
}

export function EpssDistribution({
  histogram,
  total,
  scoreDate,
}: {
  histogram: number[];
  total: number;
  scoreDate: string | null;
}) {
  const belowTen = EPSS_LOG_BINS.slice(0, 6).reduce(
    (sum, _, index) => sum + (histogram[index] ?? 0),
    0,
  );
  return (
    <div data-testid="overview-epss-chart">
      <ParentSize parentSizeStyles={{ width: "100%", height: HEIGHT }}>
        {({ width }) =>
          width > 0 ? <EpssSvg width={width} histogram={histogram} total={total} /> : null
        }
      </ParentSize>
      <p className="chart-note">
        <strong>{sharePercent(belowTen, total)}</strong> of scored records sit below a 10%
        probability. Log height keeps the tail visible.{" "}
        {scoreDate !== null ? `Score date ${scoreDate}.` : "No accepted score date."}
      </p>
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">EPSS log-bucket distribution</caption>
            <thead>
              <tr>
                <th scope="col">EPSS bucket</th>
                <th scope="col">Records</th>
                <th scope="col">Share</th>
              </tr>
            </thead>
            <tbody>
              {EPSS_LOG_BINS.map((bin, index) => (
                <tr key={bin.label}>
                  <th scope="row">{bin.label}</th>
                  <td>{formatInt(histogram[index] ?? 0)}</td>
                  <td>{sharePercent(histogram[index] ?? 0, total)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
