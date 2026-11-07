"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";

import { formatInt, sharePercent } from "./chartTokens";
import type { SankeyLink, TimeToKev } from "@/lib/time-to-kev";

// Symmetric gutters: left labels, flow, right labels. The chart is not
// stretched to the panel width, so the two label columns stay balanced
// instead of leaving a dead margin on one side.
const WIDTH = 860;
const HEIGHT = 360;
const COL_LEFT = 178;
const COL_RIGHT = 642;
const NODE_WIDTH = 14;
const PAD = 10;
const MARGIN_TOP = 16;
const MARGIN_BOTTOM = 16;

interface PlacedNode {
  id: string;
  label: string;
  column: "cohort" | "lag";
  total: number;
  x: number;
  y: number;
  height: number;
}

/**
 * Two-column Sankey: publication cohort → days until KEV confirmation.
 *
 * Deterministic layout (no simulation): each column stacks its nodes in the
 * order the caller supplies and distributes height by count, so the same data
 * always draws the same picture. Every band carries a `<title>` with the exact
 * count and share, and the same series is available as a data table.
 */

const PAGE_SIZE = 10;

/**
 * Records inside one flow. The browser is a result set, not a dump: filter by
 * CVE id, page through, and follow any record into the corpus. `count` is the
 * exact flow size while the sample is capped, so the header never overclaims.
 */
function FlowDetails({
  detail,
  labelOf,
  onClose,
}: {
  detail: { from: string; to: string; cveIds: string[]; count: number } | null;
  labelOf: (id: string) => string;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const dialog = ref.current;
    if (dialog === null) return;
    if (detail !== null && !dialog.open) dialog.showModal();
    if (detail === null && dialog.open) dialog.close();
  }, [detail]);

  const needle = query.trim().toLowerCase();
  const filtered =
    detail === null
      ? []
      : detail.cveIds.filter((id) => needle === "" || id.toLowerCase().includes(needle));
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pageCount - 1);
  const visible = filtered.slice(current * PAGE_SIZE, current * PAGE_SIZE + PAGE_SIZE);

  return (
    <dialog
      ref={ref}
      className="graph-dialog"
      aria-labelledby="flow-details-title"
      data-testid="overview-time-to-kev-dialog"
      onClose={onClose}
      onCancel={() => {
        // Escape closes natively; mirror it into state so the effect does not
        // re-open the dialog. Never preventDefault here: that blocks the close.
        onClose();
      }}
      onKeyDown={(event) => {
        // A `type="search"` input consumes the first Escape to clear its own
        // text, so the dialog would stay open. Close explicitly instead.
        if (event.key === "Escape") onClose();
      }}
      onClick={(event) => {
        if (event.target === ref.current) onClose();
      }}
    >
      {detail === null ? null : (
        <div className="graph-dialog-body">
          <header className="graph-dialog-head">
            <div>
              <div className="eyebrow">Flow details</div>
              <h2 id="flow-details-title">
                {labelOf(detail.from)} → {labelOf(detail.to)}
              </h2>
              <p className="chart-note">
                {formatInt(detail.count)} records in this flow.
                {detail.count > detail.cveIds.length
                  ? ` Showing the first ${formatInt(detail.cveIds.length)} by CVE id.`
                  : ""}
              </p>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={onClose}
              data-testid="flow-details-close"
            >
              Close
            </button>
          </header>

          <div className="graph-dialog-tools">
            <input
              className="ledger-search-input"
              type="search"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
              placeholder="Filter by CVE id"
              aria-label="Filter these records"
              data-testid="flow-details-filter"
            />
            <span className="chart-note" data-testid="flow-details-count">
              {filtered.length === 0 ? "No match" : `${formatInt(filtered.length)} matching`}
            </span>
          </div>

          <ul className="graph-dialog-list" data-testid="flow-details-list">
            {visible.map((id) => (
              <li key={id} className="graph-dialog-row">
                <div className="graph-dialog-row-head">
                  <Link
                    className="mono graph-dialog-id"
                    href={`/explore?q=${encodeURIComponent(id)}`}
                    data-testid={`flow-details-item-${id}`}
                  >
                    {id}
                  </Link>
                  <span className="graph-dialog-badges">
                    <a
                      className="graph-evidence-chip"
                      href={`https://www.cve.org/CVERecord?id=${id}`}
                      target="_blank"
                      rel="noreferrer noopener"
                    >
                      official record
                    </a>
                  </span>
                </div>
              </li>
            ))}
          </ul>

          {pageCount > 1 ? (
            <nav className="graph-dialog-pager" aria-label="Record pages">
              <button
                type="button"
                className="btn btn-sm"
                disabled={current === 0}
                onClick={() => setPage(current - 1)}
                data-testid="flow-details-prev"
              >
                Previous
              </button>
              <span className="chart-note" data-testid="flow-details-page">
                Page {current + 1} of {pageCount}
              </span>
              <button
                type="button"
                className="btn btn-sm"
                disabled={current >= pageCount - 1}
                onClick={() => setPage(current + 1)}
                data-testid="flow-details-next"
              >
                Next
              </button>
            </nav>
          ) : null}
        </div>
      )}
    </dialog>
  );
}

export function TimeToKevSankey({ flow }: { flow: TimeToKev }) {
  const [hover, setHover] = useState<string | null>(null);
  // Clicking a band pins it (Escape or a second click clears) so the reader can
  // open its details without holding the pointer steady.
  const [pinned, setPinned] = useState<string | null>(null);
  const [detail, setDetail] = useState<{
    from: string;
    to: string;
    cveIds: string[];
    count: number;
  } | null>(null);

  const { nodes, links } = useMemo(() => {
    const left = flow.nodes.filter((node) => node.column === "cohort");
    const right = flow.nodes.filter((node) => node.column === "lag");
    const usableHeight = HEIGHT - MARGIN_TOP - MARGIN_BOTTOM;
    const place = (list: typeof left, x: number): PlacedNode[] => {
      const gaps = Math.max(0, list.length - 1) * PAD;
      const space = usableHeight - gaps;
      const total = list.reduce((sum, node) => sum + node.total, 0);
      let cursor = MARGIN_TOP;
      return list.map((node) => {
        const height = total === 0 ? 0 : Math.max(2, (node.total / total) * space);
        const placed: PlacedNode = {
          id: node.id,
          label: node.label,
          column: node.column,
          total: node.total,
          x,
          y: cursor,
          height,
        };
        cursor += height + PAD;
        return placed;
      });
    };
    return { nodes: [...place(left, COL_LEFT), ...place(right, COL_RIGHT)], links: flow.links };
  }, [flow]);

  const byId = new Map(nodes.map((node) => [node.id, node]));
  // Stack each node's outgoing/incoming bands so they never overlap.
  const outgoingCursor = new Map<string, number>();
  const incomingCursor = new Map<string, number>();
  const bands = links
    .map((link: SankeyLink) => {
      const from = byId.get(link.from);
      const to = byId.get(link.to);
      if (from === undefined || to === undefined) return null;
      const totalOut = links
        .filter((entry) => entry.from === link.from)
        .reduce((sum, entry) => sum + entry.count, 0);
      const totalIn = links
        .filter((entry) => entry.to === link.to)
        .reduce((sum, entry) => sum + entry.count, 0);
      const thicknessOut = totalOut === 0 ? 0 : (link.count / totalOut) * from.height;
      const thicknessIn = totalIn === 0 ? 0 : (link.count / totalIn) * to.height;
      const y0 = (outgoingCursor.get(link.from) ?? from.y) + 0;
      outgoingCursor.set(link.from, y0 + thicknessOut);
      const y1 = (incomingCursor.get(link.to) ?? to.y) + 0;
      incomingCursor.set(link.to, y1 + thicknessIn);
      const x0 = from.x + NODE_WIDTH;
      const x1 = to.x;
      const mid = (x0 + x1) / 2;
      return {
        key: `${link.from}->${link.to}`,
        count: link.count,
        fromLabel: from.label,
        toLabel: to.label,
        thicknessOut,
        thicknessIn,
        d:
          `M ${x0} ${y0} ` +
          `C ${mid} ${y0}, ${mid} ${y1}, ${x1} ${y1} ` +
          `L ${x1} ${y1 + thicknessIn} ` +
          `C ${mid} ${y1 + thicknessIn}, ${mid} ${y0 + thicknessOut}, ${x0} ${y0 + thicknessOut} Z`,
      };
    })
    .filter((band): band is NonNullable<typeof band> => band !== null);

  const total = flow.eligible;
  const isDim = (band: { key: string }): boolean =>
    hover !== null && !band.key.startsWith(`${hover}->`) && !band.key.endsWith(`->${hover}`);

  return (
    <div className="chart-frame">
      <svg
        className="chart-svg"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Time from publication to KEV confirmation: ${formatInt(total)} records across ${nodes.filter((node) => node.column === "cohort").length} publication cohorts and ${nodes.filter((node) => node.column === "lag").length} delay buckets.`}
        data-testid="overview-time-to-kev-svg"
      >
        {bands.map((band) => (
          <path
            key={band.key}
            d={band.d}
            fill="var(--ui-accent)"
            fillOpacity={
              pinned === band.key ? 0.6 : isDim(band) ? 0.08 : hover === null ? 0.28 : 0.55
            }
            stroke={pinned === band.key ? "var(--ui-accent-deep)" : "none"}
            strokeWidth={pinned === band.key ? 1.5 : 0}
            data-testid={`overview-time-to-kev-band-${band.key}`}
            role="button"
            tabIndex={0}
            aria-pressed={pinned === band.key}
            aria-label={`${band.fromLabel} to ${band.toLabel}: ${formatInt(band.count)} records. Open details.`}
            onClick={() => {
              const key = pinned === band.key ? null : band.key;
              setPinned(key);
              if (key !== null) {
                const match = links.find((link) => `${link.from}->${link.to}` === key);
                if (match !== undefined) {
                  setDetail({
                    from: match.from,
                    to: match.to,
                    cveIds: match.cveIds,
                    count: match.count,
                  });
                }
              }
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                const key = pinned === band.key ? null : band.key;
                setPinned(key);
                if (key !== null) {
                  const match = links.find((link) => `${link.from}->${link.to}` === key);
                  if (match !== undefined) {
                    setDetail({
                      from: match.from,
                      to: match.to,
                      cveIds: match.cveIds,
                      count: match.count,
                    });
                  }
                }
              }
              if (event.key === "Escape") {
                setPinned(null);
                setDetail(null);
              }
            }}
            style={{ cursor: "pointer", outline: "none" }}
          >
            <title>{`${band.fromLabel} → ${band.toLabel}: ${formatInt(band.count)} records (${sharePercent(band.count, total)} of ${formatInt(total)} with both dates)`}</title>
          </path>
        ))}
        {nodes.map((node) => {
          const active = hover === node.id;
          return (
            <g
              key={node.id}
              tabIndex={0}
              role="button"
              aria-pressed={active}
              aria-label={`${node.label}: ${formatInt(node.total)} records, ${sharePercent(node.total, total)} of ${formatInt(total)}`}
              data-testid={`overview-time-to-kev-node-${node.column}-${node.label.replace(/\s+/g, "-")}`}
              onFocus={() => setHover(node.id)}
              onBlur={() => setHover(null)}
              onMouseEnter={() => setHover(node.id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: "pointer" }}
            >
              <rect
                x={node.x}
                y={node.y}
                width={NODE_WIDTH}
                height={node.height}
                rx={3}
                fill={active ? "var(--ui-accent-deep)" : "var(--ui-ink)"}
              />
              <text
                x={node.column === "cohort" ? node.x - 8 : node.x + NODE_WIDTH + 8}
                y={node.y + Math.min(node.height, 14) / 2 + 3.5}
                fontSize={10.5}
                textAnchor={node.column === "cohort" ? "end" : "start"}
                fontFamily="var(--ui-font-mono)"
                fill={active ? "var(--ui-accent-deep)" : "var(--ui-ink-2)"}
              >
                {node.label}
              </text>
              <text
                x={node.column === "cohort" ? node.x - 8 : node.x + NODE_WIDTH + 8}
                y={node.y + Math.min(node.height, 14) / 2 + 15}
                fontSize={9}
                textAnchor={node.column === "cohort" ? "end" : "start"}
                fontFamily="var(--ui-font-mono)"
                fill="var(--ui-ink-3)"
              >
                {formatInt(node.total)}
              </text>
            </g>
          );
        })}
      </svg>
      <FlowDetails
        detail={detail}
        labelOf={(id) => flow.nodes.find((node) => node.id === id)?.label ?? id}
        onClose={() => {
          setDetail(null);
          setPinned(null);
        }}
      />
      <p className="chart-note" data-testid="overview-time-to-kev-note">
        Left: publication cohort. Right: days until the KEV catalog confirmed exploitation. Band
        width is the record count; {formatInt(flow.excluded)} KEV records are excluded for a missing
        publication date. Hover or focus a node to isolate its flows.
      </p>
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Publication cohort by days until KEV confirmation</caption>
            <thead>
              <tr>
                <th scope="col">Publication cohort</th>
                <th scope="col">Days until confirmed</th>
                <th scope="col">Records</th>
                <th scope="col">Share</th>
              </tr>
            </thead>
            <tbody>
              {links.map((link) => {
                const from = flow.nodes.find((node) => node.id === link.from);
                const to = flow.nodes.find((node) => node.id === link.to);
                return (
                  <tr key={`${link.from}->${link.to}`}>
                    <th scope="row">{from?.label ?? link.from}</th>
                    <td>{to?.label ?? link.to}</td>
                    <td>{formatInt(link.count)}</td>
                    <td>{sharePercent(link.count, total)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
