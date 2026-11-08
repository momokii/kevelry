"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";

import { formatInt, sharePercent } from "./chartTokens";
import { FLOW_SAMPLE_CAP, type SankeyLink, type TimeToKev } from "@/lib/time-to-kev";

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

/** One flow, as the dialog and the readout need it. */
interface FlowSlice {
  key: string;
  from: string;
  to: string;
  count: number;
  cveIds: string[];
}

/**
 * What the details dialog is showing: a single band, or every flow through one
 * node. `count` is always exact; `cveIds` is a capped sample.
 */
type FlowSelection =
  | { kind: "band"; from: string; to: string; count: number; cveIds: string[] }
  | {
      kind: "node";
      nodeId: string;
      nodeColumn: "cohort" | "lag";
      count: number;
      cveIds: string[];
      flows: FlowSlice[];
    };

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
  detail: FlowSelection | null;
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
              <div className="eyebrow">
                {detail.kind === "node" ? "Node details" : "Flow details"}
              </div>
              <h2 id="flow-details-title">
                {detail.kind === "node"
                  ? `${labelOf(detail.nodeId)}: ${formatInt(detail.count)} records`
                  : `${labelOf(detail.from)} → ${labelOf(detail.to)}`}
              </h2>
              <p className="chart-note">
                {detail.kind === "node"
                  ? `Every flow through this ${detail.nodeColumn === "cohort" ? "publication cohort" : "delay bucket"}.`
                  : `${formatInt(detail.count)} records in this flow.`}
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

          {detail.kind === "node" ? (
            <ul className="sankey-flow-breakdown" data-testid="flow-details-breakdown">
              {detail.flows.map((flow) => (
                <li key={flow.key} className="sankey-flow-row">
                  <span className="sankey-flow-label">
                    {detail.nodeColumn === "cohort" ? "→ " : "← "}
                    {labelOf(detail.nodeColumn === "cohort" ? flow.to : flow.from)}
                  </span>
                  <span className="sankey-flow-count mono">{formatInt(flow.count)}</span>
                  <span className="sankey-flow-share mono">
                    {sharePercent(flow.count, detail.count)}
                  </span>
                </li>
              ))}
            </ul>
          ) : null}

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
  // Clicking a band or a node pins it (Escape or a second click clears) so the
  // highlight survives the pointer leaving the diagram.
  const [pinned, setPinned] = useState<
    { kind: "band"; key: string } | { kind: "node"; id: string } | null
  >(null);
  const [detail, setDetail] = useState<FlowSelection | null>(null);

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
  const labelOf = (id: string): string => flow.nodes.find((node) => node.id === id)?.label ?? id;
  const pinnedBandKey = pinned?.kind === "band" ? pinned.key : null;
  const pinnedNodeId = pinned?.kind === "node" ? pinned.id : null;
  // Hover is transient, the pin is not: the diagram keeps the reader's
  // selection visible after the pointer leaves.
  const focusNode = hover ?? pinnedNodeId;
  const touches = (band: { key: string }, nodeId: string): boolean =>
    band.key.startsWith(`${nodeId}->`) || band.key.endsWith(`->${nodeId}`);
  const isDim = (band: { key: string }): boolean => {
    if (pinnedBandKey !== null) return band.key !== pinnedBandKey;
    return focusNode !== null && !touches(band, focusNode);
  };
  const isActive = (band: { key: string }): boolean =>
    band.key === pinnedBandKey || (focusNode !== null && touches(band, focusNode));

  const flowsThrough = (nodeId: string): FlowSlice[] =>
    links
      .filter((link) => link.from === nodeId || link.to === nodeId)
      .map((link) => ({
        key: `${link.from}->${link.to}`,
        from: link.from,
        to: link.to,
        count: link.count,
        cveIds: link.cveIds,
      }));

  const openNode = (nodeId: string): void => {
    const node = nodes.find((entry) => entry.id === nodeId);
    if (node === undefined) return;
    const flows = flowsThrough(nodeId);
    const seen = new Set<string>();
    const sample: string[] = [];
    for (const flow of flows) {
      for (const id of flow.cveIds) {
        if (seen.has(id)) continue;
        seen.add(id);
        sample.push(id);
      }
    }
    sample.sort();
    setPinned({ kind: "node", id: nodeId });
    setDetail({
      kind: "node",
      nodeId,
      nodeColumn: node.column,
      count: node.total,
      cveIds: sample.slice(0, FLOW_SAMPLE_CAP),
      flows,
    });
  };

  const openBand = (bandKey: string): void => {
    const match = links.find((link) => `${link.from}->${link.to}` === bandKey);
    if (match === undefined) return;
    setPinned({ kind: "band", key: bandKey });
    setDetail({
      kind: "band",
      from: match.from,
      to: match.to,
      count: match.count,
      cveIds: match.cveIds,
    });
  };

  const clearSelection = (): void => {
    setPinned(null);
    setDetail(null);
  };

  const toggleBand = (bandKey: string): void => {
    if (pinnedBandKey === bandKey) {
      clearSelection();
      return;
    }
    openBand(bandKey);
  };

  const toggleNode = (nodeId: string): void => {
    if (pinnedNodeId === nodeId) {
      clearSelection();
      return;
    }
    openNode(nodeId);
  };

  // While a node is focused the readout names every flow through it with its
  // share, so the distribution is readable without opening the dialog.
  const readout =
    focusNode === null
      ? null
      : {
          node: nodes.find((node) => node.id === focusNode) ?? null,
          flows: flowsThrough(focusNode)
            .slice()
            .sort((a, b) => b.count - a.count),
        };

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
              band.key === pinnedBandKey ? 0.6 : isDim(band) ? 0.08 : isActive(band) ? 0.55 : 0.28
            }
            stroke={band.key === pinnedBandKey ? "var(--ui-accent-deep)" : "none"}
            strokeWidth={band.key === pinnedBandKey ? 1.5 : 0}
            data-testid={`overview-time-to-kev-band-${band.key}`}
            role="button"
            tabIndex={0}
            aria-pressed={band.key === pinnedBandKey}
            aria-label={`${band.fromLabel} to ${band.toLabel}: ${formatInt(band.count)} records. Open details.`}
            onClick={() => toggleBand(band.key)}
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                toggleBand(band.key);
              }
              if (event.key === "Escape") clearSelection();
            }}
            style={{ cursor: "pointer", outline: "none" }}
          >
            <title>{`${band.fromLabel} → ${band.toLabel}: ${formatInt(band.count)} records (${sharePercent(band.count, total)} of ${formatInt(total)} with both dates)`}</title>
          </path>
        ))}
        {nodes.map((node) => {
          const active = hover === node.id || pinnedNodeId === node.id;
          return (
            <g
              key={node.id}
              tabIndex={0}
              role="button"
              aria-pressed={pinnedNodeId === node.id}
              aria-label={`${node.label}: ${formatInt(node.total)} records, ${sharePercent(node.total, total)} of ${formatInt(total)}. Open its flows.`}
              data-testid={`overview-time-to-kev-node-${node.column}-${node.label.replace(/\s+/g, "-")}`}
              onFocus={() => setHover(node.id)}
              onBlur={() => setHover(null)}
              onMouseEnter={() => setHover(node.id)}
              onMouseLeave={() => setHover(null)}
              onClick={() => toggleNode(node.id)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  toggleNode(node.id);
                }
                if (event.key === "Escape") clearSelection();
              }}
              style={{ cursor: "pointer", outline: "none" }}
            >
              <rect
                x={node.x}
                y={node.y}
                width={NODE_WIDTH}
                height={node.height}
                rx={3}
                fill={active ? "var(--ui-accent-deep)" : "var(--ui-ink)"}
                stroke={pinnedNodeId === node.id ? "var(--ui-accent)" : "none"}
                strokeWidth={pinnedNodeId === node.id ? 2 : 0}
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
          // Closing the dialog keeps the selection: the highlight and the flow
          // distribution stay on the chart, and a second click (or Escape on the
          // chart) clears them.
          setDetail(null);
        }}
      />
      <div className="sankey-readout" data-testid="overview-time-to-kev-readout">
        {readout === null || readout.node === null ? (
          <p className="chart-note">
            Hover or select a cohort or a delay bucket to see how its records distribute; click
            again to pin the selection and open the records.
          </p>
        ) : (
          <>
            <div className="sankey-readout-head">
              <span className="eyebrow">
                {readout.node.column === "cohort" ? "Cohort" : "Delay"} ·{" "}
                {formatInt(readout.node.total)} records
              </span>
              <strong>{readout.node.label}</strong>
              {pinnedNodeId === readout.node.id ? (
                <span className="badge badge-accent" data-testid="overview-time-to-kev-pinned">
                  pinned
                </span>
              ) : null}
            </div>
            <ul className="sankey-flow-breakdown" data-testid="overview-time-to-kev-distribution">
              {readout.flows.map((flow) => (
                <li key={flow.key} className="sankey-flow-row">
                  <span className="sankey-flow-label">
                    {readout.node?.column === "cohort" ? "→ " : "← "}
                    {labelOf(readout.node?.column === "cohort" ? flow.to : flow.from)}
                  </span>
                  <span className="sankey-flow-count mono">{formatInt(flow.count)}</span>
                  <span className="sankey-flow-share mono">
                    {sharePercent(flow.count, readout.node?.total ?? 0)}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
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
