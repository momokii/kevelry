"use client";

import Link from "next/link";

import type { GraphCohort, GraphEdgeKind, GraphGroup } from "@/lib/graph";

const GROUP_META: Record<GraphEdgeKind, { label: string; hint: string }> = {
  cwe: { label: "Shared CWE", hint: "Same catalog weakness class" },
  vendor: { label: "Shared vendor", hint: "Same KEV vendor label" },
  domain: { label: "Shared reference host", hint: "Same advisory host" },
};

const GROUP_ORDER: readonly GraphEdgeKind[] = ["cwe", "vendor", "domain"];

const KIND_COLOR: Record<GraphEdgeKind, string> = {
  cwe: "var(--ui-critical)",
  vendor: "var(--ui-accent)",
  domain: "var(--ui-ink-3)",
};

const SVG_W = 940;
const COL_CENTER = 96;
const COL_ATTR = 372;
const COL_LEAF = 668;
const CHILD_CAP = 5;
const ATTR_CAP = 10;

interface AttrRow {
  group: GraphGroup;
  children: string[];
  hidden: number;
  height: number;
}

/**
 * Layered ego graph: center CVE -> shared attribute -> the records carrying
 * it. Deterministic layout (no force simulation), so the same data always
 * draws the same picture and every node keeps a stable position for
 * keyboard users. Labels are always rendered; nothing is inferred.
 */
function EgoGraph({ cohort, limit }: { cohort: GraphCohort; limit: number }) {
  const center = cohort.focus ?? "";
  const rows: AttrRow[] = cohort.groups.slice(0, ATTR_CAP).map((group) => {
    const children = group.cves.slice(0, CHILD_CAP);
    const hidden = Math.max(0, group.cves.length - children.length);
    return { group, children, hidden, height: (children.length + (hidden > 0 ? 1 : 0)) * 22 + 14 };
  });
  const totalHeight = Math.max(320, rows.reduce((sum, row) => sum + row.height, 0) + 24);
  const centerY = totalHeight / 2;

  let cursor = 12;
  const laid = rows.map((row) => {
    const top = cursor;
    cursor += row.height;
    return { ...row, top, mid: top + row.height / 2 };
  });

  return (
    <div className="graph-svg-wrap">
      <svg
        className="graph-svg"
        viewBox={`0 0 ${SVG_W} ${totalHeight}`}
        width="100%"
        height={totalHeight}
        role="img"
        aria-label={`Relationship graph for ${center}: ${laid.length} shared attributes and ${laid.reduce((n, row) => n + row.children.length, 0)} linked records.`}
        data-testid="graph-svg"
      >
        {laid.map((row) => {
          const color = KIND_COLOR[row.group.kind];
          return (
            <g key={`${row.group.kind}:${row.group.value}`}>
              <line
                x1={COL_CENTER + 14}
                y1={centerY}
                x2={COL_ATTR - 10}
                y2={row.mid}
                stroke={color}
                strokeWidth={1.4}
                strokeOpacity={0.55}
              />
              {row.children.map((childId, index) => {
                const y = row.top + 16 + index * 22;
                return (
                  <g key={childId}>
                    <line
                      x1={COL_ATTR + 10}
                      y1={row.mid}
                      x2={COL_LEAF - 8}
                      y2={y}
                      stroke={color}
                      strokeWidth={1}
                      strokeOpacity={0.32}
                    />
                    <a
                      href={`/graph?focus=${encodeURIComponent(childId)}&limit=${limit}`}
                      aria-label={`Center on ${childId}`}
                    >
                      <circle cx={COL_LEAF} cy={y} r={3.5} fill={color} fillOpacity={0.85} />
                      <text
                        x={COL_LEAF + 10}
                        y={y + 3.5}
                        fontSize={10}
                        fontFamily="var(--ui-font-mono)"
                        fill="var(--ui-ink-2)"
                      >
                        {childId}
                      </text>
                    </a>
                  </g>
                );
              })}
              {row.hidden > 0 ? (
                <text
                  x={COL_LEAF}
                  y={row.top + 16 + row.children.length * 22 + 4}
                  fontSize={9.5}
                  fontFamily="var(--ui-font-mono)"
                  fill="var(--ui-ink-3)"
                >
                  +{row.hidden} more
                </text>
              ) : null}
              <circle
                cx={COL_ATTR}
                cy={row.mid}
                r={Math.min(11, 5 + Math.log2(row.group.cves.length + 1))}
                fill={color}
                fillOpacity={0.9}
              />
              <text
                x={COL_ATTR - 18}
                y={row.mid + 4}
                fontSize={10.5}
                textAnchor="end"
                fontFamily="var(--ui-font-mono)"
                fill="var(--ui-ink)"
              >
                {row.group.value.length > 26 ? `${row.group.value.slice(0, 25)}…` : row.group.value}
              </text>
              <text
                x={COL_ATTR + 16}
                y={row.mid + 3.5}
                fontSize={9}
                fontFamily="var(--ui-font-mono)"
                fill="var(--ui-ink-3)"
              >
                {row.group.cves.length}
              </text>
            </g>
          );
        })}
        <circle cx={COL_CENTER} cy={centerY} r={13} fill="var(--ui-ink)" />
        <text
          x={COL_CENTER}
          y={centerY + 30}
          fontSize={10.5}
          textAnchor="middle"
          fontFamily="var(--ui-font-mono)"
          fill="var(--ui-ink)"
        >
          {center}
        </text>
      </svg>
    </div>
  );
}

function GroupColumn({
  group,
  centerId,
  limit,
}: {
  group: GraphGroup;
  centerId: string;
  limit: number;
}) {
  const meta = GROUP_META[group.kind];
  const cweNumber = group.kind === "cwe" ? group.value.replace("CWE-", "") : null;
  return (
    <section className="graph-group" data-testid={`graph-group-${group.kind}-${group.value}`}>
      <header className="graph-group-head">
        <strong className="graph-group-value">
          {cweNumber === null ? (
            group.value
          ) : (
            <a
              href={`https://cwe.mitre.org/data/definitions/${cweNumber}.html`}
              target="_blank"
              rel="noreferrer noopener"
            >
              {group.value}
            </a>
          )}
        </strong>
        <span className="graph-group-count">
          {group.cves.length} record{group.cves.length === 1 ? "" : "s"}
        </span>
      </header>
      <p className="chart-note graph-group-hint">{meta.hint}</p>
      <ul className="graph-group-list">
        {group.cves.slice(0, 8).map((id) => (
          <li key={id}>
            <Link className="mono" href={`/graph?focus=${encodeURIComponent(id)}&limit=${limit}`}>
              {id}
            </Link>
          </li>
        ))}
        {group.cves.length > 8 ? (
          <li className="graph-group-more">
            +{group.cves.length - 8} more with {centerId}
          </li>
        ) : null}
      </ul>
    </section>
  );
}

export function GraphView({ cohort, limit }: { cohort: GraphCohort; limit: number }) {
  const centerNode =
    cohort.focus === null ? null : (cohort.nodes.find((node) => node.id === cohort.focus) ?? null);

  if (cohort.focus === null) {
    return (
      <div data-testid="graph-landing">
        <p className="chart-note" data-testid="graph-coverage">
          {cohort.eligibleCohort} KEV-listed records in the retained snapshot. These are the most
          connected: each shares an attribute with the most peers. Pick one to see exactly what
          links it to the rest.
        </p>
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
            placeholder="Or center on any KEV CVE ID, e.g. CVE-2021-44228"
            aria-label="Center the graph on a CVE ID"
            maxLength={32}
            data-testid="graph-focus-input"
          />
          <input type="hidden" name="limit" value={String(limit)} />
          <button className="ledger-search-button" type="submit" data-testid="graph-focus-submit">
            Center
          </button>
        </form>
        {cohort.hubs.length === 0 ? (
          <div className="empty-state" data-testid="graph-empty">
            <strong>No KEV cohort to rank</strong>
            The retained snapshot holds no KEV-listed published records.
          </div>
        ) : (
          <ol className="graph-hubs" data-testid="graph-hubs">
            {cohort.hubs.map((hub) => (
              <li key={hub.id} className="graph-hub" data-testid={`graph-hub-${hub.id}`}>
                <div className="graph-hub-main">
                  <Link
                    className="mono graph-hub-id"
                    href={`/graph?focus=${encodeURIComponent(hub.id)}&limit=${limit}`}
                  >
                    {hub.id}
                  </Link>
                  <span className="graph-hub-title">{hub.title}</span>
                </div>
                <div className="graph-hub-signals">
                  <span className="badge badge-unknown">{hub.degree} links</span>
                  {hub.epss !== null ? (
                    <span className="badge badge-accent">
                      EPSS {(Number(hub.epss) * 100).toFixed(2)}%
                    </span>
                  ) : null}
                  {hub.kevDueDate !== null ? (
                    <span className="badge badge-high">due {hub.kevDueDate}</span>
                  ) : null}
                </div>
                <ul className="graph-hub-attrs">
                  {hub.topAttributes.map((attribute) => (
                    <li key={`${attribute.kind}:${attribute.value}`}>
                      <span className="graph-evidence-kind">
                        {GROUP_META[attribute.kind].label}
                      </span>
                      <span className="graph-evidence-chip">
                        {attribute.value} · {attribute.cves.length}
                      </span>
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ol>
        )}
        <p className="chart-note">
          Links are labeled facts only: a shared KEV catalog CWE, the same normalized vendor label,
          or a shared advisory host (with aggregator hosts excluded). Nothing is inferred from text
          similarity.
        </p>
      </div>
    );
  }

  const groupsByKind = GROUP_ORDER.map((kind) => ({
    kind,
    groups: cohort.groups.filter((group) => group.kind === kind),
  })).filter((entry) => entry.groups.length > 0);

  return (
    <div data-testid="graph-centered">
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
          placeholder="Center on another KEV CVE ID"
          aria-label="Center the graph on a CVE ID"
          maxLength={32}
          data-testid="graph-focus-input"
        />
        <input type="hidden" name="limit" value={String(limit)} />
        <button className="ledger-search-button" type="submit" data-testid="graph-focus-submit">
          Center
        </button>
        <Link className="btn btn-sm" href={`/graph?limit=${limit}`} data-testid="graph-clear">
          Back to hubs
        </Link>
      </form>

      <div className="graph-center" data-testid="graph-center">
        <div>
          <div className="eyebrow">Centered on</div>
          <h2 className="graph-center-id mono">{cohort.focus}</h2>
          <p className="chart-note">{centerNode?.title ?? cohort.focus}</p>
        </div>
        <dl className="density-stats graph-center-stats">
          <div>
            <dt>Links</dt>
            <dd data-testid="graph-center-degree">{centerNode?.degree ?? 0}</dd>
          </div>
          <div>
            <dt>Severity</dt>
            <dd>{centerNode?.band ?? "unscored"}</dd>
          </div>
          <div>
            <dt>EPSS</dt>
            <dd>{centerNode?.epss ?? "unknown"}</dd>
          </div>
          <div>
            <dt>Remediation due</dt>
            <dd>{centerNode?.kevDueDate ?? "none stated"}</dd>
          </div>
        </dl>
        <div className="result-actions">
          <Link className="btn btn-sm" href={`/explore?q=${encodeURIComponent(cohort.focus)}`}>
            Open in Search
          </Link>
          <Link className="btn btn-sm" href={`/watch`}>
            Watch list
          </Link>
        </div>
      </div>

      <p className="chart-note" data-testid="graph-coverage">
        {cohort.groups.reduce((sum, group) => sum + group.cves.length, 0)} shared-attribute links
        across {cohort.groups.length} attribute{cohort.groups.length === 1 ? "" : "s"}
        {cohort.truncated ? " · bounded, not complete" : ""}. Click any CVE to re-center on it.
      </p>

      {groupsByKind.length === 0 ? (
        <div className="empty-state" data-testid="graph-no-links">
          <strong>No labeled links for this record</strong>
          It shares no catalog CWE, vendor label, or advisory host with another KEV record. That is
          a fact about the retained data, not a missing feature.
        </div>
      ) : (
        <>
          <EgoGraph cohort={cohort} limit={limit} />
          <ul className="graph-legend" data-testid="graph-legend">
            {GROUP_ORDER.map((kind) => (
              <li key={kind}>
                <span className="graph-legend-swatch" style={{ background: KIND_COLOR[kind] }} />
                {GROUP_META[kind].label}
              </li>
            ))}
          </ul>
          <div className="graph-columns" data-testid="graph-columns">
            {groupsByKind.map((entry) => (
              <div key={entry.kind} className="graph-column">
                <h3 className="graph-column-head">{GROUP_META[entry.kind].label}</h3>
                {entry.groups.map((group) => (
                  <GroupColumn
                    key={`${group.kind}:${group.value}`}
                    group={group}
                    centerId={cohort.focus ?? ""}
                    limit={limit}
                  />
                ))}
              </div>
            ))}
          </div>
        </>
      )}

      <details className="chart-table">
        <summary>Data table</summary>
        <div className="table-wrap">
          <table className="data-table">
            <caption className="sr-only">Shared attributes and the records carrying them</caption>
            <thead>
              <tr>
                <th scope="col">Kind</th>
                <th scope="col">Value</th>
                <th scope="col">Records</th>
                <th scope="col">CVE IDs</th>
              </tr>
            </thead>
            <tbody>
              {cohort.groups.map((group) => (
                <tr key={`${group.kind}:${group.value}`}>
                  <th scope="row">{GROUP_META[group.kind].label}</th>
                  <td>{group.value}</td>
                  <td>{group.cves.length}</td>
                  <td className="mono">{group.cves.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
      <p className="chart-note">
        Selection is a fact list, not a graph hairball: each group is one shared attribute and the
        KEV records that carry it. Advisory aggregator hosts (securityfocus, exploit-db and peers)
        are excluded because sharing a citation aggregator says nothing about relatedness.
      </p>
    </div>
  );
}
