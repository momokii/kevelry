"use client";

import { useState } from "react";

import { isSeverityBand } from "../explore/filter-meta";
import { ChartTable } from "./ChartTable";
import { SEVERITY_META, SEVERITY_ORDER, formatInt, sharePercent } from "./chartTokens";

const SIZE = 220;
const CENTER = SIZE / 2;
const RADIUS = 82;
const STROKE = 26;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export function SeverityDonut({ bands, total }: { bands: Record<string, number>; total: number }) {
  const [active, setActive] = useState<string | null>(null);
  const segments: Array<{ band: string; count: number; length: number; offset: number }> = [];
  let offset = 0;
  for (const band of SEVERITY_ORDER) {
    const count = bands[band] ?? 0;
    if (count <= 0 || total <= 0) continue;
    const length = (count / total) * CIRCUMFERENCE;
    segments.push({ band, count, length, offset });
    offset += length;
  }
  const selected = active === null ? null : SEVERITY_META[active as keyof typeof SEVERITY_META];
  const selectedCount = active === null ? total : (bands[active] ?? 0);

  return (
    <div data-testid="overview-severity-donut">
      <div className="donut-layout">
        <div className="donut-wrap">
          {/*
            A group, not an image: each segment is a link to the same
            severity-filtered Explore view the legend uses, and `role="img"`
            would flatten those links out of the tree.
          */}
          <svg
            viewBox={`0 0 ${SIZE} ${SIZE}`}
            className="donut"
            role="group"
            aria-label={`Severity composition of ${formatInt(total)} published CVEs. Each segment opens that band in Explore.`}
          >
            <circle
              cx={CENTER}
              cy={CENTER}
              r={RADIUS}
              fill="none"
              stroke="var(--ui-rule-soft)"
              strokeWidth={STROKE}
            />
            {segments.map((segment) => {
              const meta = SEVERITY_META[segment.band as keyof typeof SEVERITY_META];
              const isActive = active === segment.band;
              // A segment acts only when Explore accepts its band as a filter
              // value. Anything else stays a labelled, non-interactive mark:
              // never a button that does nothing.
              const filterable = isSeverityBand(segment.band);
              const ring = (
                <circle
                  cx={CENTER}
                  cy={CENTER}
                  r={RADIUS}
                  fill="none"
                  stroke={meta.color}
                  strokeWidth={isActive ? STROKE + 4 : STROKE}
                  strokeDasharray={`${Math.max(0.5, segment.length - 2)} ${CIRCUMFERENCE}`}
                  strokeDashoffset={-segment.offset}
                  transform={`rotate(-90 ${CENTER} ${CENTER})`}
                />
              );
              const name = `${meta.label}: ${formatInt(segment.count)} published, ${sharePercent(segment.count, total)} of the corpus.`;
              const highlight = {
                onMouseEnter: () => setActive(segment.band),
                onMouseLeave: () => setActive(null),
                onFocus: () => setActive(segment.band),
                onBlur: () => setActive(null),
              };
              return filterable ? (
                <a
                  key={segment.band}
                  href={`/explore?severity=${segment.band}`}
                  aria-label={`${name} Open in Explore.`}
                  data-testid={`overview-donut-segment-${segment.band}`}
                  style={{ cursor: "pointer" }}
                  {...highlight}
                >
                  {ring}
                </a>
              ) : (
                <g
                  key={segment.band}
                  role="img"
                  aria-label={name}
                  data-testid={`overview-donut-segment-${segment.band}`}
                >
                  {ring}
                </g>
              );
            })}
            <text x={CENTER} y={CENTER - 6} textAnchor="middle" className="donut-center-label">
              {selected === null ? "published" : selected.label}
            </text>
            <text x={CENTER} y={CENTER + 26} textAnchor="middle" className="donut-center-value">
              {formatInt(selectedCount)}
            </text>
            {selected !== null ? (
              <text x={CENTER} y={CENTER + 46} textAnchor="middle" className="donut-center-sub">
                {sharePercent(selectedCount, total)}
              </text>
            ) : null}
          </svg>
        </div>
        <ul className="donut-legend" data-testid="overview-severity-list">
          {SEVERITY_ORDER.map((band) => {
            const meta = SEVERITY_META[band];
            const count = bands[band] ?? 0;
            return (
              <li key={band}>
                <a
                  href={`/explore?severity=${band}`}
                  className={`donut-legend-row ${active === band ? "is-active" : ""}`}
                  data-testid={`overview-severity-${band}`}
                  onMouseEnter={() => setActive(band)}
                  onMouseLeave={() => setActive(null)}
                  onFocus={() => setActive(band)}
                  onBlur={() => setActive(null)}
                  aria-label={`${meta.label}: ${formatInt(count)} published, ${sharePercent(count, total)}. Open in Explore.`}
                >
                  <span
                    className="severity-dot"
                    style={{ background: meta.color }}
                    aria-hidden="true"
                  />
                  <span>{meta.short}</span>
                  <strong>{formatInt(count)}</strong>
                  <span className="faint">{sharePercent(count, total)}</span>
                </a>
              </li>
            );
          })}
        </ul>
      </div>
      <ChartTable
        caption="Severity composition"
        rows={SEVERITY_ORDER}
        rowKey={(band) => band}
        emptyMessage="No severity band in this cohort."
        columns={[
          {
            key: "band",
            header: "Band",
            value: (band) => SEVERITY_META[band].label,
          },
          {
            key: "published",
            header: "Published",
            value: (band) => formatInt(bands[band] ?? 0),
          },
          {
            key: "share",
            header: "Share",
            value: (band) => sharePercent(bands[band] ?? 0, total),
          },
        ]}
      />
    </div>
  );
}
