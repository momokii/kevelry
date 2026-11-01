"use client";

import Link from "next/link";
import { useState } from "react";

import type { GraphCohort, GraphEdgeKind } from "@/lib/graph";

const WIDTH = 640;
const HEIGHT = 420;
const CENTER_X = 320;
const CENTER_Y = 210;
const RING_RADIUS = 155;

const EDGE_STYLE: Record<GraphEdgeKind, { dash: string; label: string }> = {
  cwe: { dash: "", label: "shared catalog CWE" },
  vendor: { dash: "6 4", label: "shared vendor label" },
  domain: { dash: "2 4", label: "shared reference host" },
};

function positionFor(index: number, total: number, isFocus: boolean): { x: number; y: number } {
  if (isFocus || total <= 1) return { x: CENTER_X, y: CENTER_Y };
  const angle = (2 * Math.PI * index) / total - Math.PI / 2;
  return {
    x: CENTER_X + RING_RADIUS * Math.cos(angle),
    y: CENTER_Y + RING_RADIUS * Math.sin(angle),
  };
}

export function GraphView({ cohort, limit }: { cohort: GraphCohort; limit: number }) {
  // Pinned selection (click/Enter, survives blur so inspector links stay
  // usable) vs transient keyboard preview (focus without pinning). A click
  // must never toggle itself off via the focus it also triggers.
  const [pinned, setPinned] = useState<string | null>(cohort.focus);
  const [preview, setPreview] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const selected = pinned ?? preview;
  const positions = new Map(
    cohort.nodes.map((node, index) => [
      node.id,
      positionFor(index, cohort.nodes.length, node.id === cohort.focus),
    ]),
  );
  const selectedNode = cohort.nodes.find((node) => node.id === selected) ?? null;
  const selectedEdges =
    selected === null
      ? []
      : cohort.edges.filter((edge) => edge.from === selected || edge.to === selected);
  // Aggregate the actual shared attributes behind every incident link so the
  // inspector answers "linked by WHAT", not just "how many".
  const sharedCwes = new Map<string, number>();
  const sharedDomains = new Map<string, number>();
  const sharedVendors = new Map<string, number>();
  for (const edge of selectedEdges) {
    for (const cwe of edge.evidence.cwes) sharedCwes.set(cwe, (sharedCwes.get(cwe) ?? 0) + 1);
    for (const host of edge.evidence.domains) {
      sharedDomains.set(host, (sharedDomains.get(host) ?? 0) + 1);
    }
    if (edge.evidence.vendor !== null) {
      sharedVendors.set(edge.evidence.vendor, (sharedVendors.get(edge.evidence.vendor) ?? 0) + 1);
    }
  }
  const topCwes = [...sharedCwes].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, 6);
  const topDomains = [...sharedDomains]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, 5);
  const topVendors = [...sharedVendors]
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .slice(0, 3);

  return (
    <div>
      <form
        className="ledger-search"
        method="get"
        action="/graph"
        role="search"
        data-testid="graph-focus-form"
      >
        <input
          className="ledger-search-input"
          type="search"
          name="focus"
          defaultValue={cohort.focus ?? ""}
          placeholder="Center on a CVE ID, e.g. CVE-2026-109618"
          aria-label="Center the graph on a CVE ID"
          maxLength={32}
          data-testid="graph-focus-input"
        />
        <input type="hidden" name="limit" value={String(limit)} />
        <button className="ledger-search-button" type="submit" data-testid="graph-focus-submit">
          Center
        </button>
      </form>
      <p className="chart-note" data-testid="graph-coverage">
        {cohort.nodes.length} of {cohort.eligibleCohort} KEV-listed records
        {cohort.focus === null ? "" : ` · centered on ${cohort.focus} (most-connected hub)`}
        {cohort.truncated ? " · bounded, not complete" : ""} · {cohort.edges.length} labeled links.
      </p>
      {cohort.nodes.length === 0 ? (
        <div className="empty-state" data-testid="graph-empty">
          <strong>No KEV cohort to graph</strong>
          The retained snapshot holds no KEV-listed published records. This is an honest empty
          state, not a zero baseline.
        </div>
      ) : (
        <div className="density-layout" data-testid="graph-layout">
          <svg
            className="chart-svg"
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            role="img"
            aria-label={`Relationship graph: ${cohort.nodes.length} records, ${cohort.edges.length} labeled links.`}
            data-testid="graph-svg"
          >
            {cohort.edges.map((edge) => {
              const from = positions.get(edge.from);
              const to = positions.get(edge.to);
              if (from === undefined || to === undefined) return null;
              const primary = edge.kinds[0] ?? "cwe";
              const dimmed = selected !== null && edge.from !== selected && edge.to !== selected;
              return (
                <line
                  key={`${edge.from}|${edge.to}`}
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke="var(--ui-ink-3)"
                  strokeOpacity={dimmed ? 0.25 : 0.75}
                  strokeWidth={1.5}
                  strokeDasharray={
                    EDGE_STYLE[primary].dash === "" ? undefined : EDGE_STYLE[primary].dash
                  }
                >
                  <title>{edge.kinds.map((kind) => EDGE_STYLE[kind].label).join(", ")}</title>
                </line>
              );
            })}
            {cohort.nodes.map((node) => {
              const at = positions.get(node.id) ?? { x: CENTER_X, y: CENTER_Y };
              const isFocus = node.id === cohort.focus;
              const isSelected = node.id === selected;
              const labeled = isFocus || isSelected || node.id === hovered;
              return (
                <g
                  key={node.id}
                  tabIndex={0}
                  role="button"
                  aria-pressed={isSelected}
                  aria-label={`${node.id}, ${node.degree} links. Select to inspect.`}
                  data-testid={`graph-node-${node.id}`}
                  transform={`translate(${at.x} ${at.y})`}
                  onClick={() => setPinned(pinned === node.id ? null : node.id)}
                  onFocus={() => setPreview(node.id)}
                  onBlur={() => setPreview(null)}
                  onMouseEnter={() => setHovered(node.id)}
                  onMouseLeave={() => setHovered(null)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      setPinned(pinned === node.id ? null : node.id);
                    }
                    if (event.key === "Escape") {
                      setPinned(null);
                      setPreview(null);
                    }
                  }}
                  style={{ cursor: "pointer", outline: "none" }}
                >
                  <circle
                    r={isFocus ? 10 : 5 + Math.min(4, node.degree)}
                    fill={isSelected ? "var(--ui-accent)" : "var(--ui-surface)"}
                    stroke={isSelected ? "var(--ui-accent-deep)" : "var(--ui-ink-2)"}
                    strokeWidth={isSelected ? 3 : 1.5}
                  />
                  {labeled ? (
                    <text
                      textAnchor="middle"
                      dy={isFocus ? 24 : 20}
                      fontSize={9}
                      fontFamily="var(--ui-font-mono)"
                      fill="var(--ui-ink-2)"
                    >
                      {node.id.replace("CVE-", "")}
                    </text>
                  ) : null}
                </g>
              );
            })}
          </svg>
          <aside
            className="density-inspector"
            aria-label="Selected record"
            data-testid="graph-inspector"
          >
            <div className="eyebrow">Selected record</div>
            {selectedNode === null ? (
              <p className="chart-note" data-testid="graph-inspector-empty">
                Hover or focus a node. Click to pin the inspector; Escape clears it.
              </p>
            ) : (
              <>
                <h3 data-testid="graph-inspector-id">{selectedNode.id}</h3>
                <p className="chart-note" data-testid="graph-inspector-title">
                  {selectedNode.title}
                </p>
                <div className="density-big" data-testid="graph-inspector-degree">
                  {selectedNode.degree}
                  <span> links</span>
                </div>
                <dl className="density-stats">
                  <div>
                    <dt>Severity</dt>
                    <dd>{selectedNode.band ?? "unscored"}</dd>
                  </div>
                  <div>
                    <dt>EPSS</dt>
                    <dd>{selectedNode.epss ?? "unknown"}</dd>
                  </div>
                  <div>
                    <dt>Remediation due</dt>
                    <dd>{selectedNode.kevDueDate ?? "none stated"}</dd>
                  </div>
                </dl>
                {selectedEdges.length > 0 ? (
                  <div className="graph-evidence" data-testid="graph-inspector-evidence">
                    <div className="eyebrow">Linked by</div>
                    {topCwes.length > 0 ? (
                      <p className="graph-evidence-line">
                        <span className="graph-evidence-kind">CWE</span>
                        {topCwes.map(([cwe, count]) => (
                          <a
                            key={cwe}
                            className="graph-evidence-chip"
                            href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
                            target="_blank"
                            rel="noreferrer noopener"
                          >
                            {cwe} · {count}
                          </a>
                        ))}
                      </p>
                    ) : null}
                    {topVendors.length > 0 ? (
                      <p className="graph-evidence-line">
                        <span className="graph-evidence-kind">Vendor</span>
                        {topVendors.map(([vendor, count]) => (
                          <span key={vendor} className="graph-evidence-chip">
                            {vendor} · {count}
                          </span>
                        ))}
                      </p>
                    ) : null}
                    {topDomains.length > 0 ? (
                      <p className="graph-evidence-line">
                        <span className="graph-evidence-kind">Host</span>
                        {topDomains.map(([host, count]) => (
                          <span key={host} className="graph-evidence-chip">
                            {host} · {count}
                          </span>
                        ))}
                      </p>
                    ) : null}
                  </div>
                ) : null}
                <div className="stack" style={{ gap: 8 }}>
                  <Link
                    className="btn btn-sm"
                    href={`/graph?focus=${encodeURIComponent(selectedNode.id)}&limit=${limit}`}
                  >
                    Center on this record
                  </Link>
                  <Link
                    className="btn btn-sm"
                    href={`/explore?q=${encodeURIComponent(selectedNode.id)}`}
                  >
                    Open in Search
                  </Link>
                </div>
              </>
            )}
          </aside>
        </div>
      )}
      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Graphed records and link counts</caption>
            <thead>
              <tr>
                <th scope="col">CVE ID</th>
                <th scope="col">Title</th>
                <th scope="col">Links</th>
              </tr>
            </thead>
            <tbody>
              {cohort.nodes.map((node) => (
                <tr key={node.id}>
                  <th scope="row">{node.id}</th>
                  <td>{node.title}</td>
                  <td>{node.degree}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <p className="chart-note">
        Line style names the link kind: solid for shared CWE, dashed for shared vendor, dotted for
        shared reference host. Node size grows with link count. The cohort and caps are stated
        above; nothing is sampled silently.
      </p>
    </div>
  );
}
