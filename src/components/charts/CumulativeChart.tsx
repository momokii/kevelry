"use client";

import { useMemo, useState } from "react";

import { AxisBottom, AxisLeft } from "@visx/axis";
import { GridRows } from "@visx/grid";
import { Group } from "@visx/group";
import { ParentSize } from "@visx/responsive";
import { scaleLinear } from "@visx/scale";

import { formatCompact, formatInt, monthLong, monthShort, sharePercent } from "./chartTokens";

const MARGIN = { top: 16, right: 10, bottom: 26, left: 44 };
const HEIGHT = 208;

interface Point {
  month: string;
  count: number;
  cumulative: number;
}

function CumulativeSvg({ width, points }: { width: number; points: Point[] }) {
  const [active, setActive] = useState<number | null>(null);
  const innerWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const max = points[points.length - 1]?.cumulative ?? 1;
  const x = useMemo(
    () =>
      scaleLinear<number>({
        domain: [0, Math.max(1, points.length - 1)],
        range: [0, innerWidth],
      }),
    [innerWidth, points.length],
  );
  const y = useMemo(
    () =>
      scaleLinear<number>({
        domain: [0, max * 1.06],
        range: [innerHeight, 0],
        nice: true,
      }),
    [innerHeight, max],
  );
  const line = points
    .map((point, index) => `${index === 0 ? "M" : "L"}${x(index)},${y(point.cumulative)}`)
    .join(" ");
  const area = `${line} L${x(points.length - 1)},${innerHeight} L${x(0)},${innerHeight} Z`;
  const activePoint = active === null ? null : points[active];
  const tickValues = points.filter((_, index) => index % 4 === 0).map((point) => point.month);

  return (
    <div className="chart-frame" onMouseLeave={() => setActive(null)}>
      {activePoint !== undefined && activePoint !== null ? (
        <div className="chart-tooltip" style={{ left: 6, top: 4 }}>
          <div className="tt-label">{monthLong(activePoint.month)}</div>
          <div className="tt-value">{formatInt(activePoint.cumulative)}</div>
          <div className="tt-share">
            cumulative in window · +{formatInt(activePoint.count)} that month
          </div>
        </div>
      ) : null}
      <svg
        className="chart-svg"
        width={width}
        height={HEIGHT}
        viewBox={`0 0 ${width} ${HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label={`Cumulative published CVEs in the displayed window, ending at ${formatInt(max)}.`}
      >
        <Group left={MARGIN.left} top={MARGIN.top}>
          <GridRows
            scale={y}
            width={innerWidth}
            height={innerHeight}
            numTicks={3}
            stroke="var(--ui-rule-soft)"
            strokeDasharray="3 4"
          />
          <path d={area} fill="var(--ui-accent)" fillOpacity={0.08} />
          <path d={line} fill="none" stroke="var(--ui-accent)" strokeWidth={2} />
          {points.map((point, index) => (
            <g key={point.month}>
              <circle
                cx={x(index)}
                cy={y(point.cumulative)}
                r={active === index ? 4 : 2.5}
                fill="var(--ui-accent)"
              />
              <circle
                cx={x(index)}
                cy={y(point.cumulative)}
                r={10}
                fill="transparent"
                tabIndex={0}
                role="button"
                aria-label={`${monthLong(point.month)}: ${formatInt(point.cumulative)} cumulative, ${formatInt(point.count)} published that month.`}
                onMouseEnter={() => setActive(index)}
                onFocus={() => setActive(index)}
                onBlur={() => setActive(null)}
                onKeyDown={(event) => {
                  if (event.key === "Escape") setActive(null);
                }}
              />
            </g>
          ))}
          <AxisLeft
            scale={y}
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
            scale={x}
            top={innerHeight}
            tickValues={tickValues.map((_, index) => index * 4)}
            tickFormat={(value) => monthShort(points[Number(value)]?.month ?? "")}
            tickLength={3}
            tickLabelProps={() => ({
              fill: "var(--ui-ink-3)",
              fontSize: 8.5,
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

export function CumulativeChart({
  months,
  publishedTotal,
}: {
  months: Array<{ month: string; count: number }>;
  publishedTotal: number;
}) {
  let running = 0;
  const points = months.map((entry) => {
    running += entry.count;
    return { ...entry, cumulative: running };
  });
  const first = points[0];
  const last = points[points.length - 1];
  if (first === undefined || last === undefined) {
    return <p className="empty-state">No publication history in this window.</p>;
  }
  return (
    <div data-testid="overview-cumulative">
      <ParentSize parentSizeStyles={{ width: "100%", height: HEIGHT }}>
        {({ width }) => (width > 0 ? <CumulativeSvg width={width} points={points} /> : null)}
      </ParentSize>
      <p className="chart-note">
        <strong>{formatInt(last.cumulative)}</strong> publications accumulated inside this window (
        {sharePercent(last.cumulative, publishedTotal)} of the current corpus). The line is
        cumulative, not a forecast; older records outside the window are not shown.
      </p>
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th scope="col">Month</th>
                <th scope="col">Published</th>
                <th scope="col">Cumulative</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.month}>
                  <th scope="row">{monthLong(point.month)}</th>
                  <td>{formatInt(point.count)}</td>
                  <td>{formatInt(point.cumulative)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
