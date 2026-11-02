"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

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
const ATTR_CAP = 6;
/** Vertical budget so the drawing fits a normal viewport without clipping. */
const MAX_HEIGHT = 680;
const ROW_UNIT = 22;

interface AttrRow {
  group: GraphGroup;
  children: string[];
  hidden: number;
  height: number;
}

/**
 * Full list for one shared attribute. Native <dialog> gives focus trapping,
 * Escape-to-close, and backdrop semantics for free; the trigger is always a
 * real button, so keyboard users reach it without a pointer.
 */
function MoreDialog({
  group,
  centerId,
  limit,
  onClose,
}: {
  group: GraphGroup | null;
  centerId: string;
  limit: number;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (dialog === null) return;
    if (group !== null && !dialog.open) dialog.showModal();
    if (group === null && dialog.open) dialog.close();
  }, [group]);

  return (
    <dialog
      ref={ref}
      className="graph-dialog"
      aria-labelledby="graph-dialog-title"
      data-testid="graph-more-dialog"
      onClose={onClose}
      onClick={(event) => {
        // Backdrop click: the dialog element itself is the backdrop area.
        if (event.target === ref.current) onClose();
      }}
    >
      {group === null ? null : (
        <div className="graph-dialog-body">
          <header className="graph-dialog-head">
            <div>
              <div className="eyebrow">{GROUP_META[group.kind].label}</div>
              <h2 id="graph-dialog-title" className="mono">
                {group.value}
              </h2>
              <p className="chart-note">
                {group.cves.length} KEV-listed records share this with {centerId}.{" "}
                {GROUP_META[group.kind].hint}.
              </p>
            </div>
            <button
              type="button"
              className="btn btn-sm"
              onClick={onClose}
              data-testid="graph-more-close"
            >
              Close
            </button>
          </header>
          <ul className="graph-dialog-list" data-testid="graph-more-list">
            {group.cves.map((id) => (
              <li key={id}>
                <Link
                  className="mono"
                  href={`/graph?focus=${encodeURIComponent(id)}&limit=${limit}`}
                  data-testid={`graph-more-item-${id}`}
                >
                  {id}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </dialog>
  );
}

/**
 * Layered ego graph: center CVE -> shared attribute -> the records carrying
 * it. Deterministic layout (no force simulation), so the same data always
 * draws the same picture and every node keeps a stable position for
 * keyboard users. Labels are always rendered; nothing is inferred.
 */
function EgoGraph({
  cohort,
  limit,
  onMore,
}: {
  cohort: GraphCohort;
  limit: number;
  onMore: (group: GraphGroup) => void;
}) {
  const center = cohort.focus ?? "";
  const shown = cohort.groups.slice(0, ATTR_CAP);
  // Child budget per attribute from the available height, so the center and
  // every edge stay inside the viewBox instead of being clipped.
  const perRow = shown.length === 0 ? ROW_UNIT : MAX_HEIGHT / shown.length;
  // Reserve one slot for the "+N more" line so the last row never clips.
  const childCap = Math.max(1, Math.min(5, Math.floor((perRow - 14) / ROW_UNIT) - 1));
  const rows: AttrRow[] = shown.map((group) => {
    const children = group.cves.slice(0, childCap);
    const hidden = Math.max(0, group.cves.length - children.length);
    return {
      group,
      children,
      hidden,
      height: (children.length + (hidden > 0 ? 1 : 0)) * ROW_UNIT + 14,
    };
  });
  // Keep the whole drawing inside a normal viewport: the center must be
  // visible without scrolling, or the graph reads as a fragment.
  const totalHeight = Math.max(
    320,
    Math.min(620, rows.reduce((sum, row) => sum + row.height, 0) + 24),
  );
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
                const y = row.top + 16 + index * ROW_UNIT;
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
                <g
                  role="button"
                  tabIndex={0}
                  aria-label={`Show all ${row.group.cves.length} records sharing ${row.group.value}`}
                  data-testid={`graph-more-${row.group.kind}-${row.group.value}`}
                  className="graph-more-trigger"
                  onClick={() => onMore(row.group)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      onMore(row.group);
                    }
                  }}
                >
                  <rect
                    x={COL_LEAF - 6}
                    y={row.top + 16 + row.children.length * ROW_UNIT - 6}
                    width={110}
                    height={18}
                    rx={4}
                    fill="var(--ui-surface-raised)"
                    stroke="var(--ui-rule)"
                  />
                  <text
                    x={COL_LEAF + 4}
                    y={row.top + 16 + row.children.length * ROW_UNIT + 6}
                    fontSize={9.5}
                    fontFamily="var(--ui-font-mono)"
                    fill="var(--ui-ink-2)"
                  >
                    +{row.hidden} more · view all
                  </text>
                </g>
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

/**
 * Plain-language reading guide. The graph is only honest if a reader can tell
 * what a node is, what a line means, and what it does NOT mean; this block is
 * that contract in the product itself, not only in the docs.
 */
function GraphGuide({ centered }: { centered: boolean }) {
  return (
    <details className="graph-guide" data-testid="graph-guide" open={!centered}>
      <summary>How to read this graph</summary>
      <div className="graph-guide-body">
        <section>
          <h3>What a dot is</h3>
          <p>
            One <strong>KEV-listed CVE</strong> from the retained snapshot — a record CISA has
            confirmed as exploited. Records that are not on the KEV catalog are not drawn, because
            the cohort is defined by that catalog, not by popularity or by the CVE year.
          </p>
        </section>
        <section>
          <h3>What a line means</h3>
          <p>
            A line is a <strong>shared attribute</strong> between the two records, and it is always
            one of exactly three kinds:
          </p>
          <ul>
            <li>
              <strong>Shared CWE</strong> (red) — both records carry the same catalog weakness
              identifier, e.g. <code>CWE-94</code> (code injection). Same <em>class</em> of flaw,
              not the same code.
            </li>
            <li>
              <strong>Shared vendor</strong> (blue) — the KEV catalog names the same vendor label
              for both, e.g. <code>microsoft</code>. Same publisher, not necessarily the same
              product or version.
            </li>
            <li>
              <strong>Shared reference host</strong> (grey) — both records cite an advisory on the
              same hostname, e.g. <code>security.gentoo.org</code>. That usually means the same
              package family was patched across distributions.
            </li>
          </ul>
        </section>
        <section>
          <h3>What a line does not mean</h3>
          <p>
            No causality, no exploit chain, no &quot;affects the same system&quot;, no severity
            equivalence. Two records sharing <code>CWE-787</code> are not more dangerous together;
            they just share a weakness class. Nothing here is inferred from text similarity, machine
            learning, or popularity — if there is no shared attribute, there is no line.
          </p>
        </section>
        <section>
          <h3>How the numbers work</h3>
          <p>
            The number beside an attribute is <strong>how many KEV records carry it</strong> — the
            denominator is always stated. <code>+N more · view all</code> opens the complete list
            for that attribute; the drawing shows only the first few so the shape stays readable.
            The cohort caps are printed above the drawing; a capped view says so and is never
            presented as complete.
          </p>
        </section>
        <section>
          <h3>How to move around</h3>
          <p>
            Click any CVE to <strong>center</strong> on it — the graph redraws around that record.
            <strong> Graph overview</strong> (top left) returns to the ranked hub list. Every node
            is keyboard reachable: Tab to it, Enter to open.
          </p>
        </section>
        <section>
          <h3>Why some hosts are missing</h3>
          <p>
            Advisory aggregators — <code>securityfocus.com</code>, <code>exploit-db.com</code>,
            <code> nvd.nist.gov</code> and peers — are excluded. Almost every record cites them, so
            sharing one says nothing about relatedness; keeping them would link everything to
            everything and destroy the signal.
          </p>
        </section>
      </div>
    </details>
  );
}

export function GraphView({ cohort, limit }: { cohort: GraphCohort; limit: number }) {
  const [more, setMore] = useState<GraphGroup | null>(null);
  const centerNode =
    cohort.focus === null ? null : (cohort.nodes.find((node) => node.id === cohort.focus) ?? null);

  if (cohort.focus === null) {
    return (
      <div data-testid="graph-landing">
        <GraphGuide centered={false} />
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
      <nav className="graph-back" aria-label="Breadcrumb">
        <Link href={`/graph?limit=${limit}`} data-testid="graph-back">
          <span aria-hidden="true">←</span> Graph overview
        </Link>
        <span className="graph-back-sep" aria-hidden="true">
          /
        </span>
        <Link href={`/explore?q=${encodeURIComponent(cohort.focus ?? "")}`}>Search records</Link>
      </nav>
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
          Clear center
        </Link>
      </form>

      <GraphGuide centered />
      <div className="graph-center" data-testid="graph-center">
        <div>
          <div className="eyebrow">Centered on</div>
          <h2 className="graph-center-id mono" data-testid="graph-center-id">
            {cohort.focus}
          </h2>
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
          <EgoGraph cohort={cohort} limit={limit} onMore={setMore} />
          <p className="chart-note" data-testid="graph-scope">
            Graph shows the {Math.min(cohort.groups.length, 6)} strongest shared attributes; the
            grouped lists below cover all {cohort.groups.length}.
          </p>
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
      <MoreDialog
        group={more}
        centerId={cohort.focus ?? ""}
        limit={limit}
        onClose={() => setMore(null)}
      />
      <p className="chart-note">
        Selection is a fact list, not a graph hairball: each group is one shared attribute and the
        KEV records that carry it. Advisory aggregator hosts (securityfocus, exploit-db and peers)
        are excluded because sharing a citation aggregator says nothing about relatedness.
      </p>
    </div>
  );
}
