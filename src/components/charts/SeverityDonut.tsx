"use client";

import { useState } from "react";

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
          <svg
            viewBox={`0 0 ${SIZE} ${SIZE}`}
            className="donut"
            role="img"
            aria-label={`Severity composition of ${formatInt(total)} published CVEs. Hover or focus a segment for details.`}
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
              return (
                <circle
                  key={segment.band}
                  cx={CENTER}
                  cy={CENTER}
                  r={RADIUS}
                  fill="none"
                  stroke={meta.color}
                  strokeWidth={isActive ? STROKE + 4 : STROKE}
                  strokeDasharray={`${Math.max(0.5, segment.length - 2)} ${CIRCUMFERENCE}`}
                  strokeDashoffset={-segment.offset}
                  transform={`rotate(-90 ${CENTER} ${CENTER})`}
                  tabIndex={0}
                  role="button"
                  aria-label={`${meta.label}: ${formatInt(segment.count)} published, ${sharePercent(segment.count, total)} of the corpus.`}
                  onMouseEnter={() => setActive(segment.band)}
                  onMouseLeave={() => setActive(null)}
                  onFocus={() => setActive(segment.band)}
                  onBlur={() => setActive(null)}
                  onKeyDown={(event) => {
                    if (event.key === "Escape") setActive(null);
                  }}
                  style={{ cursor: "pointer" }}
                />
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
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Severity composition</caption>
            <thead>
              <tr>
                <th scope="col">Band</th>
                <th scope="col">Published</th>
                <th scope="col">Share</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITY_ORDER.map((band) => (
                <tr key={band}>
                  <th scope="row">{SEVERITY_META[band].label}</th>
                  <td>{formatInt(bands[band] ?? 0)}</td>
                  <td>{sharePercent(bands[band] ?? 0, total)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
