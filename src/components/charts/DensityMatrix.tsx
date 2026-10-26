"use client";

import { useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";

import type { SeverityEpssCell } from "@/lib/aggregates";

import {
  EPSS_LOG_BINS,
  SEVERITY_META,
  SEVERITY_ORDER,
  formatInt,
  sharePercent,
  type SeverityKey,
} from "./chartTokens";

type CellRef = { band: SeverityKey; bin: number };

function keyOf(band: string, bin: number): string {
  return `${band}:${bin}`;
}

export function DensityMatrix({
  cells,
  publishedTotal,
  epssScored,
}: {
  cells: SeverityEpssCell[];
  publishedTotal: number;
  epssScored: number;
}) {
  const byKey = useMemo(() => {
    const map = new Map<string, SeverityEpssCell>();
    for (const cell of cells) map.set(keyOf(cell.band, cell.bin), cell);
    return map;
  }, [cells]);

  const initial = useMemo<CellRef>(() => {
    let best: CellRef = { band: "critical", bin: 0 };
    let bestKev = -1;
    for (const band of SEVERITY_ORDER) {
      for (let bin = 0; bin < EPSS_LOG_BINS.length; bin += 1) {
        const cell = byKey.get(keyOf(band, bin));
        if (cell !== undefined && cell.kev > bestKev) {
          bestKev = cell.kev;
          best = { band, bin };
        }
      }
    }
    return best;
  }, [byKey]);

  const [selected, setSelected] = useState<CellRef>(initial);
  const [hover, setHover] = useState<CellRef | null>(null);
  const refs = useRef(new Map<string, HTMLButtonElement>());

  const maxCount = useMemo(() => Math.max(1, ...cells.map((cell) => cell.count)), [cells]);
  const selectedCell = byKey.get(keyOf(selected.band, selected.bin));
  const selectedMeta = SEVERITY_META[selected.band];
  const selectedLabel = EPSS_LOG_BINS[selected.bin]?.label ?? "";
  const hoverCell = hover === null ? null : (byKey.get(keyOf(hover.band, hover.bin)) ?? null);
  const hoverMeta = hover === null ? null : SEVERITY_META[hover.band];

  const move = (bandIndex: number, binIndex: number, deltaBand: number, deltaBin: number): void => {
    const nextBand = Math.min(SEVERITY_ORDER.length - 1, Math.max(0, bandIndex + deltaBand));
    const nextBin = Math.min(EPSS_LOG_BINS.length - 1, Math.max(0, binIndex + deltaBin));
    const next = { band: SEVERITY_ORDER[nextBand] ?? "critical", bin: nextBin };
    setSelected(next);
    requestAnimationFrame(() => refs.current.get(keyOf(next.band, next.bin))?.focus());
  };

  return (
    <div className="density-layout" data-testid="overview-density">
      <div>
        <div className="matrix-readout">
          {hover !== null && hoverCell !== null && hoverMeta !== null ? (
            <>
              <strong>
                {hoverMeta.label} × EPSS {EPSS_LOG_BINS[hover.bin]?.label}
              </strong>{" "}
              · {formatInt(hoverCell.count)} CVEs · KEV {formatInt(hoverCell.kev)}
            </>
          ) : (
            <>
              Hover or focus a cell. Use arrow keys to move; the inspector follows your selection.
              Cell color is severity, darkness is log count, a ring marks KEV.
            </>
          )}
        </div>
        <p className="chart-note matrix-scroll-hint">
          Swipe horizontally to see every EPSS bucket.
        </p>
        <div className="matrix-scroll">
          <div className="matrix" role="group" aria-label="CVSS severity by EPSS probability">
            <div className="matrix-corner">severity \ EPSS</div>
            {EPSS_LOG_BINS.map((bin) => (
              <div key={bin.label} className="matrix-col-label">
                {bin.label}
              </div>
            ))}
            {SEVERITY_ORDER.map((band, bandIndex) => {
              const meta = SEVERITY_META[band];
              return (
                <div key={band} className="matrix-row" style={{ display: "contents" }}>
                  <div className="matrix-row-label">
                    <span
                      className="severity-dot"
                      style={{ background: meta.color }}
                      aria-hidden="true"
                    />
                    {meta.label}
                  </div>
                  {EPSS_LOG_BINS.map((bin, binIndex) => {
                    const cell = byKey.get(keyOf(band, binIndex));
                    const count = cell?.count ?? 0;
                    const kev = cell?.kev ?? 0;
                    const isSelected = selected.band === band && selected.bin === binIndex;
                    const density = count === 0 ? 0 : 0.12 + 0.8 * Math.sqrt(count / maxCount);
                    return (
                      <button
                        key={bin.label}
                        type="button"
                        ref={(node) => {
                          if (node !== null) refs.current.set(keyOf(band, binIndex), node);
                          else refs.current.delete(keyOf(band, binIndex));
                        }}
                        className={`matrix-cell ${isSelected ? "is-selected" : ""} ${kev > 0 ? "has-kev" : ""}`}
                        data-testid={`overview-density-cell-${band}-${binIndex}`}
                        style={
                          { "--cell-color": meta.color, "--cell-alpha": density } as CSSProperties
                        }
                        tabIndex={isSelected ? 0 : -1}
                        aria-pressed={isSelected}
                        aria-label={`${meta.label}, EPSS ${bin.label}: ${formatInt(count)} CVEs, ${formatInt(kev)} KEV-listed.`}
                        onMouseEnter={() => setHover({ band, bin: binIndex })}
                        onMouseLeave={() => setHover(null)}
                        onFocus={() => setHover({ band, bin: binIndex })}
                        onBlur={() => setHover(null)}
                        onClick={() => setSelected({ band, bin: binIndex })}
                        onKeyDown={(event) => {
                          if (event.key === "ArrowRight") {
                            event.preventDefault();
                            move(bandIndex, binIndex, 0, 1);
                          } else if (event.key === "ArrowLeft") {
                            event.preventDefault();
                            move(bandIndex, binIndex, 0, -1);
                          } else if (event.key === "ArrowDown") {
                            event.preventDefault();
                            move(bandIndex, binIndex, 1, 0);
                          } else if (event.key === "ArrowUp") {
                            event.preventDefault();
                            move(bandIndex, binIndex, -1, 0);
                          } else if (event.key === "Home") {
                            event.preventDefault();
                            move(bandIndex, binIndex, 0, -binIndex);
                          } else if (event.key === "End") {
                            event.preventDefault();
                            move(bandIndex, binIndex, 0, EPSS_LOG_BINS.length - 1 - binIndex);
                          }
                        }}
                      >
                        <span className="matrix-fill" aria-hidden="true" />
                        <span className="matrix-count">{count > 0 ? formatInt(count) : "·"}</span>
                        {kev > 0 ? <span className="matrix-kev" aria-hidden="true" /> : null}
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
        <p className="chart-note">
          <strong>{formatInt(epssScored)}</strong> records have a current EPSS row;{" "}
          {formatInt(Math.max(0, publishedTotal - epssScored))} are not on the probability axis.
          Unscored CVSS is an explicit row, never zero severity. KEV rings mark cells containing at
          least one catalog entry.
        </p>
      </div>

      <aside
        className="density-inspector"
        aria-label="Selected cohort"
        data-testid="overview-density-inspector"
      >
        <div className="eyebrow">Selected cell</div>
        <h3>
          {selectedMeta.label} × EPSS {selectedLabel}
        </h3>
        <div className="density-big" data-testid="overview-density-count">
          {formatInt(selectedCell?.count ?? 0)}
          <span> CVEs</span>
        </div>
        <dl className="density-stats">
          <div>
            <dt>Share of corpus</dt>
            <dd>{sharePercent(selectedCell?.count ?? 0, publishedTotal)}</dd>
          </div>
          <div>
            <dt>Share of EPSS-scored</dt>
            <dd>{sharePercent(selectedCell?.count ?? 0, epssScored)}</dd>
          </div>
          <div>
            <dt>KEV-listed</dt>
            <dd>{formatInt(selectedCell?.kev ?? 0)}</dd>
          </div>
          <div>
            <dt>KEV rate in cell</dt>
            <dd>
              {(selectedCell?.count ?? 0) > 0
                ? sharePercent(selectedCell?.kev ?? 0, selectedCell?.count ?? 0)
                : "—"}
            </dd>
          </div>
        </dl>
        <p className="signal-note">
          {selectedMeta.note}.{" "}
          {selected.band === "legacy"
            ? "Legacy v2 scores are not compared with v3/v4."
            : selected.band === "unknown"
              ? "No primary CNA metric was supplied; this is not a low score."
              : `Primary CNA score range ${selectedMeta.range}.`}
        </p>
        <div className="stack" style={{ gap: 8 }}>
          <a className="btn btn-sm" href={`/explore?severity=${selected.band}`}>
            Open this severity band
          </a>
          <a className="btn btn-sm" href="/priority?view=highest-forecast">
            Highest forecast list
          </a>
        </div>
      </aside>
    </div>
  );
}
