"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { AxisBottom, AxisLeft } from "@visx/axis";
import { GridRows } from "@visx/grid";
import { Group } from "@visx/group";
import { ParentSize } from "@visx/responsive";
import { scaleBand, scaleLinear } from "@visx/scale";

import { dailyWindow, monthExploreHref, weeklyVolume } from "@/components/overview/chartData";

import { formatCompact, formatInt, monthLong, monthShort, sharePercent } from "./chartTokens";

export interface VolumeDatum {
  month: string;
  count: number;
}

type VolumeChartProps = {
  months: VolumeDatum[];
  publishedTotal: number;
  /** Daily counts for the trailing window; enables week/day granularity. */
  daily?: VolumeDatum[];
  kevMonths?: Array<{ month: string; count: number }>;
};

type Granularity = "month" | "week" | "day";

const WINDOWS: Record<Granularity, readonly number[]> = {
  month: [12, 24],
  week: [26, 52],
  day: [30, 90],
};

const DAY_LABELS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

function labelFor(granularity: Granularity, key: string): string {
  if (granularity === "month") return monthLong(key);
  const [year, month, day] = key.split("-");
  const monthName = DAY_LABELS[Number(month) - 1] ?? month;
  return granularity === "week"
    ? `week of ${Number(day)} ${monthName} ${year}`
    : `${Number(day)} ${monthName} ${year}`;
}

function shortLabel(granularity: Granularity, key: string): string {
  if (granularity === "month") return monthShort(key);
  const [, month, day] = key.split("-");
  return `${Number(day)} ${DAY_LABELS[Number(month) - 1] ?? month}`;
}

const MARGIN = { top: 24, right: 10, bottom: 26, left: 44 };
const HEIGHT = 286;

function VolumeSvg({
  width,
  months,
  publishedTotal,
  selected,
  onSelect,
  granularity,
}: {
  width: number;
  months: VolumeDatum[];
  publishedTotal: number;
  selected: string | null;
  onSelect: (month: string | null) => void;
  granularity: Granularity;
}) {
  const [hover, setHover] = useState<{ month: string; x: number; y: number } | null>(null);
  const innerWidth = Math.max(0, width - MARGIN.left - MARGIN.right);
  const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;

  const xScale = useMemo(
    () =>
      scaleBand<string>({
        domain: months.map((entry) => entry.month),
        range: [0, innerWidth],
        padding: 0.24,
      }),
    [months, innerWidth],
  );
  const max = Math.max(1, ...months.map((entry) => entry.count));
  const yScale = useMemo(
    () =>
      scaleLinear<number>({
        domain: [0, max * 1.12],
        range: [innerHeight, 0],
        nice: true,
      }),
    [innerHeight, max],
  );

  const peak = months.reduce(
    (best, entry) => (entry.count > best.count ? entry : best),
    months[0] ?? { month: "", count: 0 },
  );
  const tickValues = months.filter((_, index) => index % 3 === 0).map((entry) => entry.month);
  const active =
    hover === null ? null : (months.find((entry) => entry.month === hover.month) ?? null);
  const bandwidth = xScale.bandwidth();
  const tooltipLeft =
    hover === null
      ? 0
      : Math.min(Math.max(MARGIN.left + (xScale(hover.month) ?? 0) - 70, 8), width - 190);

  return (
    <div className="chart-frame" onMouseLeave={() => setHover(null)}>
      {active !== null && hover !== null ? (
        <div
          className="chart-tooltip"
          style={{ left: tooltipLeft, top: 8 }}
          data-testid="overview-volume-tooltip"
        >
          <div className="tt-label">{labelFor(granularity, active.month)}</div>
          <div className="tt-value">{formatInt(active.count)}</div>
          <div className="tt-share">
            {sharePercent(active.count, publishedTotal)} of all published CVEs
          </div>
          <div className="tt-share">UTC calendar {granularity} · click to inspect</div>
        </div>
      ) : null}
      <svg
        className="chart-svg"
        width={width}
        height={HEIGHT}
        viewBox={`0 0 ${width} ${HEIGHT}`}
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label={`Published CVE volume by UTC ${granularity}. ${months.length} buckets, peak ${formatInt(peak.count)} in ${labelFor(granularity, peak.month)}.`}
      >
        <Group left={MARGIN.left} top={MARGIN.top}>
          <GridRows
            scale={yScale}
            width={innerWidth}
            height={innerHeight}
            numTicks={4}
            stroke="var(--ui-rule-soft)"
            strokeDasharray="3 4"
          />
          {months.map((entry) => {
            const barX = xScale(entry.month) ?? 0;
            const barY = yScale(entry.count);
            const isSelected = entry.month === selected;
            const isHover = entry.month === hover?.month;
            return (
              <g key={entry.month}>
                <rect
                  className="volume-bar"
                  x={barX}
                  y={barY}
                  width={bandwidth}
                  height={Math.max(1, innerHeight - barY)}
                  rx={2}
                  fill={
                    isSelected || isHover
                      ? "var(--ui-accent)"
                      : entry.month === peak.month
                        ? "var(--ui-ink)"
                        : "var(--ui-ink)"
                  }
                  fillOpacity={isSelected || isHover ? 1 : entry.month === peak.month ? 0.9 : 0.68}
                  role="button"
                  tabIndex={0}
                  data-testid={`overview-volume-bar-${entry.month}`}
                  aria-pressed={isSelected}
                  aria-label={`${monthLong(entry.month)}: ${formatInt(entry.count)} published, ${sharePercent(entry.count, publishedTotal)} of all. Select to inspect.`}
                  onMouseEnter={() =>
                    setHover({
                      month: entry.month,
                      x: MARGIN.left + barX,
                      y: barY,
                    })
                  }
                  onFocus={() =>
                    setHover({
                      month: entry.month,
                      x: MARGIN.left + barX,
                      y: barY,
                    })
                  }
                  onBlur={() => setHover(null)}
                  onClick={() => onSelect(isSelected ? null : entry.month)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onSelect(isSelected ? null : entry.month);
                    }
                    if (event.key === "Escape") onSelect(null);
                  }}
                />
                {entry.month === peak.month && width > 520 ? (
                  <text
                    x={barX + bandwidth / 2}
                    y={barY - 7}
                    textAnchor="middle"
                    className="chart-label-strong"
                    fontSize={10}
                  >
                    peak {formatCompact(entry.count)}
                  </text>
                ) : null}
              </g>
            );
          })}
          <AxisLeft
            scale={yScale}
            numTicks={4}
            tickFormat={(value) => formatCompact(Number(value))}
            tickLength={0}
            tickLabelProps={() => ({
              fill: "var(--ui-ink-3)",
              fontSize: 10,
              fontFamily: "var(--ui-font-mono)",
              dx: -6,
              dy: 3,
              textAnchor: "end",
            })}
            axisClassName="chart-axis"
            tickStroke="transparent"
          />
          <AxisBottom
            scale={xScale}
            top={innerHeight}
            tickValues={tickValues}
            tickFormat={(value) => shortLabel(granularity, String(value))}
            tickLength={4}
            tickLabelProps={() => ({
              fill: "var(--ui-ink-3)",
              fontSize: 9.5,
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

export function VolumeChart({
  months,
  publishedTotal,
  daily = [],
  kevMonths = [],
}: VolumeChartProps) {
  const [granularity, setGranularity] = useState<Granularity>("month");
  const [windowSize, setWindowSize] = useState<number>(24);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    if (window.matchMedia("(max-width: 620px)").matches) setWindowSize(12);
  }, []);

  const weeks: VolumeDatum[] = useMemo(
    () =>
      weeklyVolume(daily.map((entry) => ({ bucketStart: entry.month, count: entry.count }))).map(
        (bucket) => ({ month: bucket.bucketStart, count: bucket.count }),
      ),
    [daily],
  );
  // One series feeds the drawing, the table, the tooltip and the selection
  // strip, so all four can never disagree about a bucket.
  const series: VolumeDatum[] =
    granularity === "month" ? months : granularity === "week" ? weeks : daily;
  const visible = series.slice(-windowSize);

  const switchGranularity = (next: Granularity): void => {
    setGranularity(next);
    setSelected(null);
    // Keep the most detailed window that still fits the chosen bucket.
    const options = WINDOWS[next];
    setWindowSize((current) =>
      options.includes(current) ? current : (options[options.length - 1] ?? 12),
    );
  };

  if (months.length === 0) {
    return (
      <div className="empty-state" data-testid="overview-chart-empty">
        <strong>No publication volume yet</strong>
        The retained snapshot holds no published records in this interval. This is an honest empty
        state, not a zero baseline.
      </div>
    );
  }
  const total = visible.reduce((sum, entry) => sum + entry.count, 0);
  const selectedEntry =
    selected === null ? null : (series.find((entry) => entry.month === selected) ?? null);
  const href = selected === null ? null : monthExploreHref(selected.slice(0, 7));
  const first = visible[0];
  const last = visible[visible.length - 1];
  const growth =
    first !== undefined && last !== undefined && first.count > 0
      ? (last.count / first.count).toFixed(1)
      : null;

  return (
    <div>
      <div className="chart-actions" style={{ marginBottom: 12 }}>
        <div className="pill segmented" role="group" aria-label="Bucket size">
          {(["month", "week", "day"] as const).map((option) => (
            <button
              key={option}
              type="button"
              className={`btn btn-sm ${granularity === option ? "btn-primary" : "btn-ghost"}`}
              aria-pressed={granularity === option}
              data-testid={`overview-volume-granularity-${option}`}
              onClick={() => switchGranularity(option)}
            >
              {option === "month" ? "Month" : option === "week" ? "Week" : "Day"}
            </button>
          ))}
        </div>
        <div className="pill segmented" role="group" aria-label="Chart window">
          {WINDOWS[granularity].map((option) => (
            <button
              key={option}
              type="button"
              className={`btn btn-sm ${windowSize === option ? "btn-primary" : "btn-ghost"}`}
              aria-pressed={windowSize === option}
              data-testid={`overview-volume-window-${option}`}
              onClick={() => setWindowSize(option)}
            >
              {option}{" "}
              {granularity === "month" ? "months" : granularity === "week" ? "weeks" : "days"}
            </button>
          ))}
        </div>
        <label className="volume-month-focus">
          <span>Focus {granularity}</span>
          <select
            className="ledger-snapshot-select"
            value={selected ?? ""}
            data-testid="overview-volume-month-select"
            onChange={(event) => setSelected(event.target.value === "" ? null : event.target.value)}
          >
            <option value="">All {granularity}s</option>
            {visible.map((entry) => (
              <option key={entry.month} value={entry.month}>
                {labelFor(granularity, entry.month)} · {formatInt(entry.count)}
              </option>
            ))}
          </select>
        </label>
        <span className="faint" style={{ fontSize: 12 }}>
          {formatInt(total)} in view
          {growth !== null ? ` · latest is ${growth}× the first ${granularity}` : ""}
        </span>
      </div>
      {selectedEntry !== null && href !== null ? (
        <div className="selection-strip" data-testid="overview-volume-selection">
          <span>
            <strong>{labelFor(granularity, selectedEntry.month)}</strong>:{" "}
            {formatInt(selectedEntry.count)} published (
            {sharePercent(selectedEntry.count, publishedTotal)} of the corpus)
            {granularity === "month" ? (
              <>
                {" · "}
                {formatInt(
                  kevMonths.find((entry) => entry.month === selectedEntry.month)?.count ?? 0,
                )}{" "}
                KEV additions
              </>
            ) : null}
          </span>
          <Link className="btn btn-sm btn-primary" href={href}>
            {granularity === "month" ? "Open this month in Explore" : "Open this range in Explore"}
          </Link>
          <button type="button" className="btn btn-sm" onClick={() => setSelected(null)}>
            Clear
          </button>
        </div>
      ) : null}
      <ParentSize parentSizeStyles={{ width: "100%", height: HEIGHT }}>
        {({ width }) =>
          width > 0 ? (
            <VolumeSvg
              width={width}
              months={visible}
              publishedTotal={publishedTotal}
              selected={selected}
              onSelect={setSelected}
              granularity={granularity}
            />
          ) : null
        }
      </ParentSize>
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Published CVE counts by UTC month</caption>
            <thead>
              <tr>
                <th scope="col">Month</th>
                <th scope="col">Published</th>
                <th scope="col">Share</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((entry) => (
                <tr key={entry.month}>
                  <th scope="row">{monthLong(entry.month)}</th>
                  <td>{formatInt(entry.count)}</td>
                  <td>{sharePercent(entry.count, publishedTotal)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
