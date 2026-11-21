"use client";

// Priority list primitives (plan todo 20; typography pass task 49).
// Presentational only: no database, no fetch, no ordering logic. The server
// component in `app/priority/page.tsx` computes every value with the priority
// services and passes rendered-ready props here. Signals render as structured
// blocks (bold key values, italic caveats, mono labels) with HelpTip
// definitions and TimeText dates; styling reuses the ledger classes from
// `app/globals.css` plus the local `PrioritySignals.module.css` grid.

import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

import type { KevRansomwareUse } from "@/lib/record-display";
import type { CweRef } from "@/lib/cwe-catalog";
import type { CvssSecondary } from "@/lib/cvss-projection";
import { displayProbabilityPercentFixed } from "../../lib/ranking";

import {
  CWE_TAXONOMY_UNAVAILABLE,
  CWE_UNMAPPED_STATE,
  KEV_RANSOMWARE_USE_LABELS,
  cweChipName,
  cweMitigations,
} from "../../lib/cwe-display";

// The state words live in `cwe-display.ts` so every renderer states them once;
// re-exported here to keep this module's existing import surface intact.
export { CWE_TAXONOMY_UNAVAILABLE, CWE_UNMAPPED_STATE };
import { ChartTable } from "../charts/ChartTable";
import { ChartTooltip, type ChartTooltipAnchor } from "../charts/ChartTooltip";
import { useRovingMarkFocus } from "../charts/useRovingMarkFocus";
import { ExploitSignal } from "../ledger/ExploitSignal";
import { HelpTip } from "../ledger/HelpTip";
import { TimeText, formatLedgerTime } from "../ledger/TimeText";
import { WatchStar } from "../ledger/WatchStar";

import styles from "./PrioritySignals.module.css";

export type PriorityMode =
  | "known-exploited"
  | "highest-forecast"
  | "new-critical"
  | "rising-forecast"
  | "kev-due-soon"
  | "ssvc-active";

export const PRIORITY_MODES: readonly PriorityMode[] = [
  "known-exploited",
  "highest-forecast",
  "new-critical",
  "rising-forecast",
  "kev-due-soon",
  "ssvc-active",
];

export const PRIORITY_MODE_LABELS: Record<PriorityMode, string> = {
  "known-exploited": "Known exploited",
  "highest-forecast": "Highest forecast",
  "new-critical": "New critical",
  "rising-forecast": "Rising forecast",
  "kev-due-soon": "KEV due soon",
  "ssvc-active": "Active exploitation (SSVC)",
};

export interface EpssTrendPoint {
  scoreDate: string;
  epss: string;
  modelVersion: string;
}

export interface PriorityRowData {
  id: string;
  title: string;
  excerpt: string | null;
  excerptTruncated: boolean;
  publishedAt: string | null;
  kevListed: boolean;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRequiredAction: string | null;
  kevVulnerabilityName: string | null;
  /** Catalog-stated use; the block branches on this, never on a boolean. */
  kevRansomwareUse: KevRansomwareUse;
  kevCwes: string[];
  /**
   * Taxonomy labels for `kevCwes`, resolved server-side (one batched lookup
   * per page). One ref per id, in the same order, so an id never disappears
   * from the block even when the catalog is absent or does not know it.
   */
  kevCweDetails: CweRef[];
  /** Accepted catalog version from the payload meta; labels the mitigation
   * disclosure. Never hard-coded in the component. Null when no catalog. */
  kevCweCatalogVersion: string | null;
  ssvc: {
    exploitation: string;
    automatable: string;
    technicalImpact: string;
    version: string | null;
    timestamp: string | null;
  } | null;
  /** References the record tags as exploit material (never "verified PoC"). */
  exploitReferences: Array<{ url: string }>;
  epssKnown: boolean;
  epssPercent: string | null;
  epssModel: string | null;
  epssDate: string | null;
  epssHistory: EpssTrendPoint[] | null;
  primaryKnown: boolean;
  primaryLegacy: boolean;
  primaryAdpOnly: boolean;
  primaryVersion: string | null;
  primaryScore: string | null;
  /**
   * Bounded, pre-ordered projection of the metrics the primary selector did
   * not pick. Rendered in the expanded severity block only, never on the
   * compact signal line, never band-coloured, never a filter or sort input.
   */
  cvssSecondary: CvssSecondary;
  deltaPp: string | null;
  deltaPreviousDate: string | null;
  officialUrl: string;
}

/** Bar width for the EPSS probability bar: the real percentage clamped to
 * 0-100, or null when the value is unknown or unparseable (never 0). */
export function epssBarWidthPercent(percentText: string | null): number | null {
  if (percentText === null) {
    return null;
  }
  const value = Number.parseFloat(percentText.trim());
  if (!Number.isFinite(value)) {
    return null;
  }
  return Math.min(100, Math.max(0, value));
}

/** Signed delta label for the rising-forecast block. The source stores plain
 * magnitudes ("8"); the sign is restored here so rows read "+8 percentage
 * points". Null and non-numeric input stay null, never "0". */
export function formatSignedDeltaPp(deltaPp: string | null): string | null {
  if (deltaPp === null) {
    return null;
  }
  const trimmed = deltaPp.trim();
  if (trimmed === "") {
    return null;
  }
  if (!Number.isFinite(Number(trimmed))) {
    return null;
  }
  const signed = trimmed.startsWith("+") || trimmed.startsWith("-") ? trimmed : `+${trimmed}`;
  return `${signed} percentage points`;
}

export type CvssBand = "critical" | "high" | "medium" | "low";

/** Severity band word for a numeric CVSS base score, using the published
 * v3.x/v4.0 ranges (critical 9.0+, high 7.0+, medium 4.0+, else low). */
export function cvssBandForScore(scoreText: string | null): CvssBand | null {
  if (scoreText === null) {
    return null;
  }
  const trimmed = scoreText.trim();
  if (trimmed === "") {
    return null;
  }
  const value = Number(trimmed);
  if (!Number.isFinite(value)) {
    return null;
  }
  if (value >= 9) {
    return "critical";
  }
  if (value >= 7) {
    return "high";
  }
  if (value >= 4) {
    return "medium";
  }
  return "low";
}

/** KEV membership state label. Both states carry a word, so the block is never
 * colour-only and absence never reads as a global fact. */
export function kevStateText(listed: boolean): string {
  return listed ? "Listed" : "Not listed";
}

/** Absent catalog fields say so in words: never a blank, never an inference. */
export const KEV_FIELD_ABSENT = "Not provided";

/** Disclosure label. The catalog version comes from the payload meta; when the
 * payload carries none the label states the reference without inventing one. */
export function cweMitigationLabel(version: string | null): string {
  const label = "Mitigation (reference, MITRE CWE";
  return version === null ? `${label})` : `${label} ${version})`;
}

export type CvssRowState = "known" | "legacy" | "adp-only" | "unscored";

export function cvssStateForRow(
  row: Pick<PriorityRowData, "primaryKnown" | "primaryLegacy" | "primaryAdpOnly">,
): CvssRowState {
  if (row.primaryKnown) {
    return "known";
  }
  if (row.primaryLegacy) {
    return "legacy";
  }
  if (row.primaryAdpOnly) {
    return "adp-only";
  }
  return "unscored";
}

export function PriorityModeNav({ current }: { current: PriorityMode }) {
  return (
    <nav
      className="ledger-filter-group"
      aria-label="Priority list modes"
      data-testid="priority-mode-nav"
    >
      {PRIORITY_MODES.map((mode) => {
        const active = mode === current;
        return active ? (
          <span
            key={mode}
            className="ledger-filter-chip"
            aria-pressed="true"
            aria-current="page"
            data-testid={`priority-tab-${mode}`}
          >
            {PRIORITY_MODE_LABELS[mode]} (current)
          </span>
        ) : (
          <a
            key={mode}
            className="ledger-filter-chip"
            aria-pressed="false"
            href={`/priority?view=${mode}`}
            data-testid={`priority-tab-${mode}`}
          >
            {PRIORITY_MODE_LABELS[mode]}
          </a>
        );
      })}
    </nav>
  );
}

export function PriorityOrdering({
  mode,
  coverage,
  extra,
  scoreDate,
  scoreModel,
  cutoffT,
}: {
  mode: PriorityMode;
  /** Denominator sentence (eligible/published/gap counts), no dates inside. */
  coverage: string;
  /** Mode-specific eligibility caveats, no dates inside. */
  extra: string;
  scoreDate: string | null;
  scoreModel: string | null;
  /** New-critical only: the window cutoff instant, rendered via TimeText. */
  cutoffT: string | null;
}) {
  const headings: Record<PriorityMode, string> = {
    "known-exploited":
      "Known exploited: KEV catalog dateAdded descending, then CVE ID ASCII ascending.",
    "highest-forecast":
      "Highest forecast: raw EPSS probability descending, known publication before unknown, publication descending, then CVE ID ASCII ascending.",
    "new-critical":
      "New critical: publication in [T - 30d, T) with primary modern (v3/v4) CNA CVSS base 9.0 or higher. Order publication descending, then CVE ID ASCII ascending.",
    "rising-forecast":
      "Rising forecast: same-model EPSS observations on exactly d and d-7 with a positive delta. Order delta percentage-points descending, current raw probability descending, then CVE ID ASCII ascending.",
    "kev-due-soon":
      "KEV due soon: KEV members with a valid catalog remediation due date. Order due date ascending (overdue first, no upper cutoff), then CVE ID ASCII ascending.",
    "ssvc-active":
      "Active exploitation (SSVC): Exploitation = active only. Order: technical impact (total first), automatable (yes first), KEV catalog date descending, raw EPSS descending, CVE ID ascending.",
  };
  return (
    <div className="ledger-ordering" data-testid={`priority-ordering-${mode}`}>
      <strong>{headings[mode]}</strong>
      <dl className={styles.defList}>
        <div>
          <dt>KEV</dt>
          <dd>
            Confirmed-exploitation evidence from the CISA catalog.{" "}
            <HelpTip term="KEV" testId={`priority-ordering-help-kev-${mode}`}>
              KEV membership means CISA lists the CVE as known to be exploited. Catalog dates mark
              catalog addition, not proven first exploitation or current attack volume.
            </HelpTip>
          </dd>
        </div>
        <div>
          <dt>EPSS</dt>
          <dd>
            Dated exploitation forecast, not observed exploitation.{" "}
            <HelpTip term="EPSS" testId={`priority-ordering-help-epss-${mode}`}>
              EPSS is a dated probability forecast from a named model version. The percent is the
              exploitation probability estimate; values are forecasts, never measurements.
            </HelpTip>
          </dd>
        </div>
        <div>
          <dt>CVSS</dt>
          <dd>
            Supplied severity from the CNA record.{" "}
            <HelpTip term="CVSS" testId={`priority-ordering-help-cvss-${mode}`}>
              CVSS here is CNA-supplied severity only. Legacy v2, ADP-only, and unscored records are
              labeled in place and never treated as low severity.
            </HelpTip>
          </dd>
        </div>
        <div>
          <dt>Score date</dt>
          <dd>
            {scoreDate !== null ? (
              <>
                EPSS score date <TimeText value={scoreDate} testId="priority-ordering-score-date" />
                {scoreModel !== null ? `, model ${scoreModel}` : ""}
              </>
            ) : (
              "No accepted EPSS score date in this snapshot."
            )}
          </dd>
        </div>
        {mode === "new-critical" && cutoffT !== null ? (
          <div>
            <dt>Window cutoff</dt>
            <dd>
              T is <TimeText value={cutoffT} testId="priority-ordering-cutoff" />
            </dd>
          </div>
        ) : null}
        <div>
          <dt>Coverage</dt>
          <dd>{coverage}</dd>
        </div>
      </dl>
      <span className="ledger-meta">{extra}</span>
    </div>
  );
}

export function PriorityEvidence({
  stale,
  detail,
  testId,
}: {
  stale: boolean;
  detail: ReactNode;
  testId: string;
}) {
  return (
    <div className="ledger-evidence" data-testid={testId}>
      <span className="ledger-evidence-symbol" aria-hidden="true">
        {stale ? "~" : "="}
      </span>
      <span className="ledger-evidence-state">{stale ? "Stale" : "Current"}</span>
      <span data-testid={`${testId}-detail`}>{detail}</span>
    </div>
  );
}

export function PrioritySummary({
  mode,
  scoreDate,
  scoreModel,
  displayed,
  eligible,
  publishedTotal,
  stale,
}: {
  mode: PriorityMode;
  scoreDate: string | null;
  scoreModel: string | null;
  displayed: number;
  eligible: number;
  publishedTotal: number;
  stale: boolean;
}) {
  return (
    <dl className={styles.summary} data-testid={`priority-summary-${mode}`}>
      <div>
        <dt>Mode</dt>
        <dd>{PRIORITY_MODE_LABELS[mode]}</dd>
      </div>
      <div>
        <dt>Score date</dt>
        <dd>
          {scoreDate !== null ? (
            <>
              <TimeText value={scoreDate} testId="priority-summary-score-date" />
              {scoreModel !== null ? ` (model ${scoreModel})` : ""}
            </>
          ) : (
            "No accepted EPSS score date"
          )}
        </dd>
      </div>
      <div>
        <dt>Showing</dt>
        <dd>
          {displayed} of {eligible} eligible ({publishedTotal} published)
        </dd>
      </div>
      <div>
        <dt>Evidence</dt>
        <dd>{stale ? "Stale" : "Current"}</dd>
      </div>
    </dl>
  );
}

/** One CWE chip: mono id, plus the published name when the taxonomy knows the
 * id. The id is never truncated and always rendered; the name truncates with an
 * ellipsis at a bounded width. Colour is never the state signal. */
function CweChip({ cwe }: { cwe: CweRef }) {
  const name = cweChipName(cwe);
  const unmapped = cwe.status === "unmapped";
  const label = [cwe.id, name, unmapped ? CWE_UNMAPPED_STATE : null].filter(
    (part): part is string => part !== null,
  );
  const body = (
    <>
      <span className={`mono ${styles.cweChipId}`} data-testid="priority-row-kev-cwe-id">
        {cwe.id}
      </span>
      {name !== null ? (
        <span className={styles.cweChipName} title={name} data-testid="priority-row-kev-cwe-name">
          {`· ${name}`}
        </span>
      ) : null}
      {unmapped ? (
        <span className={styles.cweChipState} data-testid="priority-row-kev-cwe-state">
          {CWE_UNMAPPED_STATE}
        </span>
      ) : null}
    </>
  );
  // An input with no valid CWE shape has no canonical page: plain text, never a
  // fake link. The id still renders, so nothing is ever silently dropped.
  if (cwe.url === "") {
    return (
      <span
        className={styles.cweChip}
        data-testid="priority-row-kev-cwe-chip"
        data-cwe-state={cwe.status}
      >
        {body}
      </span>
    );
  }
  return (
    <a
      className={styles.cweChip}
      href={cwe.url}
      target="_blank"
      rel="noreferrer noopener"
      aria-label={`${label.join(": ")} — MITRE CWE definition, opens in a new tab`}
      data-testid="priority-row-kev-cwe-chip"
      data-cwe-state={cwe.status}
    >
      {body}
    </a>
  );
}

/** The CWE row of the KEV block: chips for every id plus, at block level, one
 * statement when no accepted catalog is available. Mitigation text is published
 * reference material, so it stays behind a disclosure with its catalog version. */
function CweBlock({ row }: { row: PriorityRowData }) {
  const refs = row.kevCweDetails;
  const mitigations = cweMitigations(refs);
  const taxonomyUnavailable = refs.some((cwe) => cwe.status === "taxonomy-unavailable");
  // Defensive only: the page resolves every id, so refs always cover kevCwes.
  // If a caller ever omits the details, the ids still render as plain chips.
  if (refs.length === 0) {
    return (
      <ul className={styles.kevCwes}>
        {row.kevCwes.map((id) => (
          <li key={id} className={`mono ${styles.cweChipFallback}`}>
            {id}
          </li>
        ))}
      </ul>
    );
  }
  return (
    <div className={styles.cweBlock} data-testid="priority-row-kev-cwe-block">
      {taxonomyUnavailable ? (
        <p className={styles.cweBlockState} data-testid="priority-row-kev-cwe-taxonomy">
          {CWE_TAXONOMY_UNAVAILABLE}
        </p>
      ) : null}
      <ul className={styles.kevCwes}>
        {refs.map((cwe) => (
          <li key={cwe.id} className={styles.kevCweChip}>
            <CweChip cwe={cwe} />
          </li>
        ))}
      </ul>
      {mitigations.length > 0 ? (
        <details className={styles.cweMitigation} data-testid="priority-row-kev-cwe-mitigation">
          <summary data-testid="priority-row-kev-cwe-mitigation-summary">
            {cweMitigationLabel(row.kevCweCatalogVersion)}
          </summary>
          <div className={styles.cweMitigationBody}>
            <p className={styles.cweMitigationNote}>
              <HelpTip term="CWE mitigation" testId="priority-row-kev-cwe-mitigation-help">
                Published mitigation guidance from the MITRE CWE catalog, shown for context. Whether
                it applies depends on the product and the specific implementation.
              </HelpTip>{" "}
              Published guidance for context; applicability depends on the product.
            </p>
            {mitigations.map((item) => (
              <div key={item.id} className={styles.cweMitigationItem}>
                <p className={`mono ${styles.cweMitigationId}`}>{item.id}</p>
                <p
                  className={styles.cweMitigationText}
                  data-testid="priority-row-kev-cwe-mitigation-text"
                >
                  {item.mitigation}
                </p>
              </div>
            ))}
          </div>
        </details>
      ) : null}
    </div>
  );
}

function KevSignal({ row }: { row: PriorityRowData }) {
  const absent = <span className="ledger-meta">{KEV_FIELD_ABSENT}</span>;
  const requiredAction =
    row.kevRequiredAction !== null && row.kevRequiredAction.trim() !== ""
      ? row.kevRequiredAction
      : null;
  const catalogName =
    row.kevVulnerabilityName !== null && row.kevVulnerabilityName.trim() !== ""
      ? row.kevVulnerabilityName
      : null;
  return (
    <div className={styles.signal} aria-label="KEV signal" data-testid="priority-row-kev">
      <div className={styles.signalHead}>
        <span className="ledger-label">KEV</span>
        <HelpTip term="KEV (CISA catalog)" testId="priority-row-kev-help">
          KEV is catalog membership evidence: membership and its dates are catalog facts, not
          first-exploitation time, and the catalog due date is a federal remediation deadline, not a
          universal SLA. <strong>Unknown (catalog)</strong> is the catalog&apos;s own value for a
          field it published; <strong>Not stated</strong> means the field was absent from the
          catalog entry. Neither state says ransomware use is absent.
        </HelpTip>
      </div>
      <p className={styles.kevState}>
        <strong className="ledger-emphasis" data-testid="priority-row-kev-state">
          {kevStateText(row.kevListed)}
        </strong>
      </p>
      <dl className={styles.kevList}>
        <div>
          <dt>Date added (catalog)</dt>
          <dd>
            {row.kevDateAdded !== null ? (
              <TimeText value={row.kevDateAdded} testId="priority-row-kev-date" />
            ) : (
              absent
            )}
          </dd>
        </div>
        <div>
          <dt>Due date (catalog, federal context)</dt>
          <dd>
            {row.kevDueDate !== null ? (
              <TimeText value={row.kevDueDate} testId="priority-row-kev-due" />
            ) : (
              absent
            )}
          </dd>
        </div>
        <div>
          <dt>Required action</dt>
          <dd data-testid="priority-row-kev-required-action">
            {requiredAction === null ? (
              absent
            ) : (
              <>
                <span className={styles.kevSource}>Catalog-supplied</span>
                <span className={styles.kevAction}>{requiredAction}</span>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Ransomware campaign use</dt>
          <dd data-testid="priority-row-kev-ransomware">
            {KEV_RANSOMWARE_USE_LABELS[row.kevRansomwareUse]}
          </dd>
        </div>
        <div>
          <dt>Catalog name</dt>
          <dd data-testid="priority-row-kev-name">{catalogName ?? absent}</dd>
        </div>
        <div>
          <dt>CWEs</dt>
          <dd data-testid="priority-row-kev-cwes">
            {row.kevCwes.length === 0 ? absent : <CweBlock row={row} />}
          </dd>
        </div>
      </dl>
      {row.kevListed ? null : (
        <p>
          <em className="ledger-caveat">
            Absence from this catalog snapshot is not proof that exploitation never happened.
          </em>
        </p>
      )}
    </div>
  );
}

/** Score dates are UTC days, printed the way the rest of the block dates
 * things (`19 Nov 2026`), never as a raw ISO string. */
function epssDay(scoreDate: string): string {
  return formatLedgerTime(scoreDate, "UTC") ?? scoreDate;
}

/** A stored 0..1 probability as a percent with three decimals: `0.61911` →
 * `61.911%`, `0.54` → `54.000%`. One precision for the whole series — the
 * tooltip, the caption range, the data table and the live announcement all call
 * this — so no observation looks rounded next to its neighbour. The number comes
 * from the stored decimal string, so it is the exact value, never a float. */
export function formatEpssPercent(epss: string): string {
  const percent = displayProbabilityPercentFixed(epss);
  return percent === null ? epss : `${percent}%`;
}

/** The point's own reading, used by the tooltip and the live announcement. */
function epssObservationText(point: EpssTrendPoint): string {
  return `${epssDay(point.scoreDate)}: ${formatEpssPercent(point.epss)} EPSS probability`;
}

/** At most two context facts: the model that produced this observation, and
 * whether it is the window high or low. */
function epssObservationFacts(
  point: EpssTrendPoint,
  value: number,
  min: number,
  max: number,
): string[] {
  const facts: string[] = [];
  if (point.modelVersion !== "") facts.push(`model ${point.modelVersion}`);
  const high = value === max;
  const low = value === min;
  if (high && low) facts.push("series high and low");
  else if (high) facts.push("series high");
  else if (low) facts.push("series low");
  // At most two, by construction: the model, then one of high/low. `ChartTooltip`
  // truncates anything past the second fact, so nothing repeats that here.
  return facts;
}

/** One stored EPSS probability as a number in [0, 1], or null when the stored
 * value is not a number. A missing observation is null, never 0. */
export function epssTrendValues(points: ReadonlyArray<{ epss: string }>): Array<number | null> {
  return points.map((point) => {
    const text = point.epss.trim();
    if (text === "") return null;
    const parsed = Number(text);
    return Number.isFinite(parsed) ? Math.min(1, Math.max(0, parsed)) : null;
  });
}

/** Plot x for a point index, in the 0..100 viewBox. */
function trendX(index: number, count: number): number {
  return count <= 1 ? 0 : (index / (count - 1)) * 100;
}

/** Plot y for a probability, in the 0..36 viewBox (0 sits on the 34 baseline). */
function trendY(value: number): number {
  return 34 - value * 32;
}

/** A run of consecutive observations. */
export interface EpssTrendRun {
  /** Index of the run's first observation in the series. */
  start: number;
  /** Index of the run's last observation in the series. */
  end: number;
  coords: Array<{ x: number; y: number }>;
}

/**
 * Consecutive observations, oldest first.
 *
 * One polyline is drawn per run, so a missing observation is a visible break:
 * the line never interpolates across a gap and no point is plotted at zero for a
 * date that has no value.
 */
export function epssTrendRuns(values: ReadonlyArray<number | null>): EpssTrendRun[] {
  const count = values.length;
  const runs: EpssTrendRun[] = [];
  let current: EpssTrendRun | null = null;
  values.forEach((value, index) => {
    if (value === null) {
      current = null;
      return;
    }
    if (current === null) {
      current = { start: index, end: index, coords: [] };
      runs.push(current);
    }
    current.end = index;
    current.coords.push({ x: trendX(index, count), y: trendY(value) });
  });
  return runs;
}

/** Indices that carry an observation, oldest first. */
export function epssObservedIndices(values: ReadonlyArray<number | null>): number[] {
  const indices: number[] = [];
  values.forEach((value, index) => {
    if (value !== null) indices.push(index);
  });
  return indices;
}

/** How many observations in the window are absent. */
export function epssMissingCount(values: ReadonlyArray<number | null>): number {
  return values.filter((value) => value === null).length;
}

/**
 * The observation nearest a 0..1 pointer fraction, by its x position.
 *
 * A missing date is never the answer: the pointer and the keyboard skip it, so a
 * date with no value can never be shown carrying a neighbouring date's number.
 */
export function epssNearestObservedIndex(
  values: ReadonlyArray<number | null>,
  fraction: number,
): number | null {
  const count = values.length;
  const observed = epssObservedIndices(values);
  const first = observed[0];
  if (first === undefined) return null;
  const clamped = Math.min(1, Math.max(0, fraction));
  let best = first;
  let bestDistance = Math.abs(trendX(best, count) / 100 - clamped);
  for (const index of observed) {
    const distance = Math.abs(trendX(index, count) / 100 - clamped);
    if (distance < bestDistance) {
      best = index;
      bestDistance = distance;
    }
  }
  return best;
}

/** The window's lowest and highest observation, by index. A missing observation
 * never wins the comparison. */
export function epssTrendExtremes(values: ReadonlyArray<number | null>): {
  min: { index: number; value: number } | null;
  max: { index: number; value: number } | null;
} {
  let min: { index: number; value: number } | null = null;
  let max: { index: number; value: number } | null = null;
  values.forEach((value, index) => {
    if (value === null) return;
    if (min === null || value < min.value) min = { index, value };
    if (max === null || value > max.value) max = { index, value };
  });
  return { min, max };
}

/** Dated EPSS trend sparkline: linear 0..1 probability plot, oldest left.
 * Display geometry only (pixel positions); never a comparison or a score. */
export function EpssTrend({ points }: { points: EpssTrendPoint[] }) {
  const values = epssTrendValues(points);
  // A gap is not a reason to hide the figure: two dated observations and at
  // least one real value are what the plot needs, and the caption states the
  // rest. Hiding the whole figure would erase the observations that do exist.
  if (values.length < 2 || epssObservedIndices(values).length === 0) return null;
  return <EpssTrendPlot points={points} values={values} />;
}

/** The plot itself. 25–45 observations across a ~300px strip are 7–20px wide,
 * so this is one Tab stop rather than one per point: a transparent strip over
 * the plot maps pointer x to the nearest observation, Arrow/Home/End step the
 * same index from the keyboard, and the active point is marked. No value is
 * hover-only — the caption prints the window range and the disclosure lists
 * every observation. A missing observation is not a mark: the line breaks at
 * the gap and the pointer, the keyboard and the announcement skip that date.
 * The strip stays over the whole plot width, so its hit band never shrinks. */
function EpssTrendPlot({
  points,
  values,
}: {
  points: EpssTrendPoint[];
  values: Array<number | null>;
}) {
  const count = points.length;
  const observed = epssObservedIndices(values);
  const missing = epssMissingCount(values);
  const latestObserved = observed[observed.length - 1] as number;
  const runs = epssTrendRuns(values);
  const extremes = epssTrendExtremes(values);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [focused, setFocused] = useState(false);
  const [anchor, setAnchor] = useState<ChartTooltipAnchor>({ x: 0, y: 0 });
  const stripRef = useRef<HTMLDivElement | null>(null);

  const roving = useRovingMarkFocus({
    count: observed.length,
    initialIndex: observed.length - 1,
    describe: (position) => {
      const point = points[observed[position] as number];
      return point === undefined ? "" : epssObservationText(point);
    },
    onDismiss: () => {
      setHoverIndex(null);
      setFocused(false);
      stripRef.current?.blur();
    },
  });
  // `roving` counts observations, not dates: translate back to the series index.
  const active = observed[roving.activeIndex] ?? latestObserved;
  const tipIndex = hoverIndex ?? (focused ? active : null);
  const tipValue = tipIndex === null ? 0 : (values[tipIndex] ?? 0);
  // The marker follows the pointer while it is over the plot, otherwise the
  // keyboard position; the latest observation keeps its own marker either way.
  const marked = tipIndex ?? active;

  const first = points[0] as EpssTrendPoint;
  const last = points[count - 1] as EpssTrendPoint;
  // The caption range is printed from the two stored strings that bound it, at
  // the same precision as every other EPSS readout in the block.
  const minPoint = extremes.min === null ? undefined : points[extremes.min.index];
  const maxPoint = extremes.max === null ? undefined : points[extremes.max.index];
  const min = extremes.min?.value ?? 0;
  const max = extremes.max?.value ?? 0;
  const missingNote = `${missing} observation${missing === 1 ? "" : "s"} missing in the window`;

  useLayoutEffect(() => {
    if (tipIndex === null) return;
    const strip = stripRef.current;
    if (strip === null) return;
    const rect = strip.getBoundingClientRect();
    if (rect.width <= 0) return;
    setAnchor({
      x: (trendX(tipIndex, count) / 100) * rect.width,
      y: (trendY(tipValue) / 36) * rect.height,
    });
  }, [tipIndex, tipValue, count]);

  /** Nearest observation to a pointer x — the whole plot is one hit band, and a
   * missing date is skipped rather than labelled with a neighbour's value. */
  const inspect = (clientX: number) => {
    const strip = stripRef.current;
    if (strip === null) return;
    const rect = strip.getBoundingClientRect();
    if (rect.width <= 0) return;
    const index = epssNearestObservedIndex(values, (clientX - rect.left) / rect.width);
    if (index !== null) setHoverIndex(index);
  };

  const stripProps = roving.markProps(roving.activeIndex);
  const tipPoint = tipIndex === null ? undefined : points[tipIndex];

  return (
    <figure
      className={styles.trendFigure}
      role="group"
      aria-label={`EPSS trend, percent probability. ${count} dated observations, ${first.scoreDate} to ${last.scoreDate}${missing === 0 ? "" : `, ${missing} missing`}.`}
      data-testid="priority-row-epss-trend"
    >
      <div className={styles.trendPlot}>
        <svg
          className={styles.trend}
          viewBox="0 0 100 36"
          preserveAspectRatio="none"
          aria-hidden="true"
          focusable="false"
        >
          {runs.map((run) =>
            run.coords.length > 1 ? (
              <polyline
                key={`run-${run.start}`}
                data-testid={`priority-row-epss-segment-${run.start}`}
                points={run.coords.map(({ x, y }) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ")}
                fill="none"
                stroke="currentColor"
                strokeWidth={1.5}
                vectorEffect="non-scaling-stroke"
              />
            ) : run.start === latestObserved ? null : (
              // One observation between two gaps has no line to belong to, but
              // it is still data: a dot, never a line drawn across the gaps.
              <circle
                key={`run-${run.start}`}
                data-testid={`priority-row-epss-point-${run.start}`}
                cx={run.coords[0]?.x ?? 0}
                cy={run.coords[0]?.y ?? 0}
                r={1.5}
                fill="currentColor"
              />
            ),
          )}
          <circle
            data-testid="priority-row-epss-latest"
            cx={trendX(latestObserved, count)}
            cy={trendY(values[latestObserved] ?? 0)}
            r={2.5}
            fill="currentColor"
          />
          {marked === latestObserved ? null : (
            <circle
              cx={trendX(marked, count)}
              cy={trendY(values[marked] ?? 0)}
              r={2.5}
              fill="var(--ui-accent)"
            />
          )}
        </svg>
        <div
          ref={stripRef}
          className={styles.trendStrip}
          role="img"
          data-testid="priority-row-epss-strip"
          aria-label={`${observed.length} dated EPSS observations${missing === 0 ? "" : `. ${missingNote}; those dates are skipped by the pointer and the arrow keys`}. Use the arrow keys to step between them, Home and End to jump to the first and latest.`}
          tabIndex={stripProps.tabIndex}
          onFocus={() => setFocused(true)}
          onBlur={() => {
            setFocused(false);
            setHoverIndex(null);
          }}
          onKeyDown={stripProps.onKeyDown}
          onPointerMove={(event) => inspect(event.clientX)}
          onPointerDown={(event) => inspect(event.clientX)}
          onPointerLeave={(event) => {
            if (event.pointerType !== "touch") setHoverIndex(null);
          }}
        />
        {tipPoint === undefined ? null : (
          <ChartTooltip
            label={`${epssDay(tipPoint.scoreDate)} · UTC`}
            value={formatEpssPercent(tipPoint.epss)}
            unit="EPSS probability"
            context={epssObservationFacts(tipPoint, tipValue, min, max)}
            anchor={anchor}
            testId="priority-row-epss-tooltip"
          />
        )}
      </div>
      <figcaption className={styles.trendCaption}>
        {count} dated observations, {first.scoreDate} to {last.scoreDate}
        {last.modelVersion !== "" ? ` · model ${last.modelVersion}` : ""}; range{" "}
        {minPoint === undefined ? "not available" : formatEpssPercent(minPoint.epss)} to{" "}
        {maxPoint === undefined ? "not available" : formatEpssPercent(maxPoint.epss)} across the
        window{missing === 0 ? "" : `; ${missingNote} (the line breaks at each gap)`}; latest
        observation marked.
      </figcaption>
      <ChartTable
        caption="EPSS observations for this record, UTC score dates"
        summary="All observations"
        testId="priority-row-epss-table"
        rows={points}
        rowKey={(point) => point.scoreDate}
        columns={[
          {
            key: "date",
            header: "Observation date",
            value: (point) => epssDay(point.scoreDate),
          },
          {
            key: "score",
            header: "EPSS probability",
            value: (point, index) =>
              values[index] === null || values[index] === undefined
                ? "No observation"
                : formatEpssPercent(point.epss),
          },
          {
            key: "model",
            header: "Model version",
            value: (point) => (point.modelVersion === "" ? "Not stated" : point.modelVersion),
          },
        ]}
      />
      <span className={styles.srOnly} role="status">
        {focused ? roving.announcement : ""}
      </span>
    </figure>
  );
}

function EpssSignal({ row }: { row: PriorityRowData }) {
  const width = row.epssKnown ? epssBarWidthPercent(row.epssPercent) : null;
  return (
    <div className={styles.signal} aria-label="EPSS signal">
      <div className={styles.signalHead}>
        <span className="ledger-label">EPSS</span>
        <HelpTip term="EPSS" testId="priority-row-epss-help">
          A dated exploitation probability forecast from the named model version, not observed
          exploitation. Percent is the probability estimate; percentile ranks the CVE against all
          scored CVEs when supplied.
        </HelpTip>
      </div>
      {row.epssKnown && row.epssPercent !== null && width !== null ? (
        <>
          <p>
            <strong className="ledger-emphasis">{row.epssPercent}%</strong>
            {row.epssDate !== null ? (
              <>
                {" dated "}
                <TimeText value={row.epssDate} testId="priority-row-epss-date" />
              </>
            ) : null}
            {row.epssModel !== null ? `, model ${row.epssModel}` : ""}
          </p>
          <div className={styles.barTrack} aria-hidden="true">
            <span className={styles.barFill} style={{ width: `${width}%` }} />
          </div>
          <span className={styles.srOnly}>EPSS probability {row.epssPercent} percent.</span>
          {row.epssHistory !== null && row.epssHistory.length >= 2 ? (
            <EpssTrend points={row.epssHistory} />
          ) : null}
        </>
      ) : (
        <p>
          <strong className="ledger-emphasis">Unavailable</strong>
          <span> EPSS unavailable for this snapshot.</span>
        </p>
      )}
    </div>
  );
}

/**
 * Secondary metrics, inside the detail severity block only.
 *
 * Every row is neutral text: no band class, no severity colour, no badge. The
 * label and the closing line carry the guard in words, so a high ADP score can
 * never be read as this record's severity and nothing here can be filtered,
 * sorted, or promoted. Not rendered on the compact signal line.
 */
function CvssSecondaryBlock({ row }: { row: PriorityRowData }) {
  // A non-selected CNA metric is secondary too, so "nothing publishable" only
  // when the record has no primary either.
  const hasPrimary = row.primaryKnown || row.primaryLegacy;
  const metrics = row.cvssSecondary.metrics;
  return (
    <div className={styles.secondary} data-testid="priority-row-cvss-secondary">
      <div className={styles.signalHead}>
        <span className="ledger-label">Secondary (context only)</span>
        <HelpTip term="secondary CVSS" testId="priority-row-cvss-secondary-help">
          Metrics the CNA did not publish as the primary selection: ADP-published, or extra CNA
          metrics. They are shown as published and are context only — they never rank, order,
          filter, or decide eligibility, and they never replace the primary. No band is derived from
          them.
        </HelpTip>
      </div>
      {metrics.length > 0 ? (
        <ul className={styles.secondaryList}>
          {metrics.map((metric, index) => (
            <li
              key={`${metric.origin}-${metric.version}-${metric.baseScore}-${String(index)}`}
              data-testid="priority-row-cvss-secondary-metric"
            >
              <span>
                <strong className="ledger-emphasis">{metric.baseScore}</strong> v{metric.version} ·{" "}
                {metric.origin}
                {metric.provider === null ? " · provider not specified" : ` · ${metric.provider}`}
              </span>
              <span className={styles.secondaryVector}>{metric.vector}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className={styles.secondaryNote} data-testid="priority-row-cvss-secondary-empty">
          {hasPrimary
            ? "No secondary (ADP or non-selected CNA) metric published."
            : "No CNA or ADP metric published."}
        </p>
      )}
      <p className={styles.trendCaption} data-testid="priority-row-cvss-secondary-guard">
        Context only: never used for ranking, ordering, filtering, or eligibility.
      </p>
    </div>
  );
}

function CvssSignal({ row }: { row: PriorityRowData }) {
  const state = cvssStateForRow(row);
  const band = state === "known" ? cvssBandForScore(row.primaryScore) : null;
  return (
    <div className={styles.signal} aria-label="CVSS signal">
      <div className={styles.signalHead}>
        <span className="ledger-label">CVSS</span>
        <HelpTip term="CVSS" testId="priority-row-cvss-help">
          CNA-supplied severity only. Legacy v2 scores, ADP-only metrics, and unscored records are
          labeled in place; none of them means low severity.
        </HelpTip>
      </div>
      {state === "known" && row.primaryVersion !== null && row.primaryScore !== null ? (
        <p>
          Primary CNA CVSS <strong className="ledger-emphasis">{row.primaryScore}</strong> v
          {row.primaryVersion}
          {band !== null ? (
            <>
              {" "}
              <span className={styles.band}>{band}</span>
            </>
          ) : null}
        </p>
      ) : state === "legacy" && row.primaryVersion !== null && row.primaryScore !== null ? (
        <p>
          <em className="ledger-caveat">
            Legacy-scored CNA CVSS {row.primaryScore} v{row.primaryVersion}; not ranked as critical
            under this view&apos;s policy.
          </em>
        </p>
      ) : state === "adp-only" ? (
        <p>
          <em className="ledger-caveat">
            Unscored under this view&apos;s policy; ADP-only metrics are shown below as secondary
            context, never promoted.
          </em>
        </p>
      ) : (
        <p>
          <em className="ledger-caveat">Unscored under this view&apos;s policy.</em>
        </p>
      )}
      <CvssSecondaryBlock row={row} />
    </div>
  );
}

/** Record timeline from retained dates only: publication, KEV listing,
 * remediation deadline, forecast window. Missing dates leave no milestone;
 * nothing is interpolated. Display only, never a comparison. */
function StoryStrip({ row }: { row: PriorityRowData }) {
  const milestones: Array<{ key: string; label: string; date: string; testId: string }> = [];
  if (row.kevListed && row.kevDateAdded !== null) {
    milestones.push({
      key: "kev",
      label: "KEV listed",
      date: row.kevDateAdded,
      testId: "priority-row-story-kev",
    });
  }
  if (row.kevListed && row.kevDueDate !== null) {
    milestones.push({
      key: "due",
      label: "Remediation due",
      date: row.kevDueDate,
      testId: "priority-row-story-due",
    });
  }
  const history = row.epssHistory;
  if (history !== null && history.length > 0) {
    const first = history[0];
    const last = history[history.length - 1];
    if (first !== undefined && last !== undefined) {
      milestones.push({
        key: "epss",
        label: `Forecast tracked ${first.scoreDate} to ${last.scoreDate}`,
        date: last.scoreDate,
        testId: "priority-row-story-epss",
      });
    }
  }
  if (milestones.length === 0) return null;
  return (
    <ol className={styles.storyStrip} aria-label="Record timeline" data-testid="priority-row-story">
      {milestones.map((milestone) => (
        <li key={milestone.key} className={styles.storyMilestone}>
          <span className={styles.storyDot} aria-hidden="true" />
          <span>
            <span className={styles.storyLabel}>{milestone.label}</span>{" "}
            <TimeText value={milestone.date} testId={milestone.testId} />
          </span>
        </li>
      ))}
    </ol>
  );
}

/** CISA SSVC decision points, shown exactly as published. No derived score. */
function SsvcSignal({ row }: { row: PriorityRowData }) {
  if (row.ssvc === null) {
    return (
      <div className={styles.signal} aria-label="SSVC signal">
        <div className={styles.signalHead}>
          <span className="ledger-label">SSVC</span>
          <HelpTip term="SSVC" testId="priority-row-ssvc-help">
            CISA&apos;s Stakeholder-Specific Vulnerability Categorization decision points, published
            in the Vulnrichment repository. Absence means no block is published for this record — it
            is not a judgement either way.
          </HelpTip>
        </div>
        <p>
          <em className="ledger-caveat">No SSVC block published for this record.</em>
        </p>
      </div>
    );
  }
  return (
    <div className={styles.signal} aria-label="SSVC signal">
      <div className={styles.signalHead}>
        <span className="ledger-label">SSVC</span>
        <HelpTip term="SSVC" testId="priority-row-ssvc-help">
          CISA&apos;s Stakeholder-Specific Vulnerability Categorization decision points, published
          in the Vulnrichment repository. The three points are shown verbatim; this site never
          blends them into a score of its own.
        </HelpTip>
      </div>
      <p>
        <strong className="ledger-emphasis">{row.ssvc.exploitation}</strong> exploitation ·{" "}
        <strong className="ledger-emphasis">{row.ssvc.technicalImpact}</strong> technical impact ·{" "}
        automatable {row.ssvc.automatable}
      </p>
      <p className={styles.trendCaption} data-testid="priority-row-ssvc-source">
        Published by CISA{row.ssvc.version !== null ? `, SSVC ${row.ssvc.version}` : ""}
        {row.ssvc.timestamp !== null ? `, ${row.ssvc.timestamp.slice(0, 10)}` : ""}.
      </p>
    </div>
  );
}

/** CNA/ADP-tagged exploit references, linked, with the honest caveat. */
function DeltaSignal({ row }: { row: PriorityRowData }) {
  const label = formatSignedDeltaPp(row.deltaPp);
  if (label === null || row.deltaPreviousDate === null || row.epssDate === null) {
    return null;
  }
  return (
    <div className={styles.signal} aria-label="Forecast movement signal">
      <div className={styles.signalHead}>
        <span className="ledger-label">Delta</span>
        <HelpTip term="forecast movement" testId="priority-row-delta-help">
          Same-model EPSS change between the score date and seven days earlier. Missing dates and
          model transitions are ineligible, never interpolated or zeroed.
        </HelpTip>
      </div>
      <p>
        <strong className="ledger-emphasis">{label}</strong>
        {" since "}
        <TimeText value={row.deltaPreviousDate} testId="priority-row-delta-since" />
        {row.epssModel !== null ? ` (same model ${row.epssModel})` : " (same model)"}
      </p>
    </div>
  );
}

function summaryText(row: PriorityRowData): string {
  const parts: string[] = [];
  parts.push(row.kevListed ? "KEV listed" : "Not listed in KEV");
  parts.push(row.epssKnown ? `EPSS ${row.epssPercent}%` : "EPSS unavailable for this snapshot");
  if (row.primaryKnown && row.primaryScore !== null && row.primaryVersion !== null) {
    parts.push(`CVSS ${row.primaryScore} v${row.primaryVersion}`);
  } else if (row.primaryLegacy && row.primaryScore !== null) {
    parts.push(`CVSS ${row.primaryScore} v2 legacy`);
  } else if (row.primaryAdpOnly) {
    parts.push("ADP-only, unscored here");
  } else {
    parts.push("Unscored");
  }
  const delta = row.deltaPp;
  const formattedDelta = delta === null ? null : formatSignedDeltaPp(delta);
  if (formattedDelta !== null) parts.push(formattedDelta);
  return parts.join(" · ");
}

export function PriorityRow({
  row,
  defaultOpen = false,
}: {
  row: PriorityRowData;
  defaultOpen?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultOpen);
  const kevMeta = row.kevListed ? "KEV" : null;
  return (
    <article className="priority-row" data-testid="priority-row" data-cve-id={row.id}>
      <div className="priority-row-top">
        <button
          type="button"
          className="priority-row-main"
          aria-expanded={expanded}
          onClick={() => setExpanded((current) => !current)}
        >
          <span className="priority-row-ident">
            <span className="mono" data-testid="priority-row-id">
              {row.id}
            </span>
            {row.title !== row.id ? (
              <span className="priority-row-title" data-testid="priority-row-title">
                {row.title}
              </span>
            ) : null}
            <span className="priority-row-excerpt" data-testid="priority-row-excerpt">
              {row.excerpt ?? "Description not supplied"}
              {row.excerptTruncated ? " [truncated]" : ""}
            </span>
          </span>
          <span className="priority-row-signals" data-testid="priority-row-signals">
            {kevMeta !== null ? <span className="badge badge-kev">KEV</span> : null}
            {row.epssKnown && row.epssPercent !== null ? (
              <span className="badge badge-accent">EPSS {row.epssPercent}%</span>
            ) : (
              <span className="badge badge-unknown">EPSS unavailable</span>
            )}
            {row.primaryKnown && row.primaryScore !== null ? (
              <span className={`badge badge-${cvssBandForScore(row.primaryScore)}`}>
                CVSS {row.primaryScore}
              </span>
            ) : (
              <span className="badge badge-unknown">
                {row.primaryLegacy ? "Legacy v2" : row.primaryAdpOnly ? "ADP-only" : "Unscored"}
              </span>
            )}
            {row.deltaPp !== null ? (
              <span className="badge badge-high">{formatSignedDeltaPp(row.deltaPp)}</span>
            ) : null}
            <span className="priority-row-published">
              Published <TimeText value={row.publishedAt} testId="priority-row-published-date" />
            </span>
            {row.kevDateAdded !== null ? (
              <span
                className="priority-row-published priority-row-kev-added"
                data-testid="priority-row-kev-added"
                title="KEV catalog date: when CISA confirmed exploitation"
              >
                KEV added <TimeText value={row.kevDateAdded} />
              </span>
            ) : null}
            <span className="priority-chevron" aria-hidden="true">
              {expanded ? "−" : "+"}
            </span>
            <span className="sr-only">{summaryText(row)}</span>
          </span>
        </button>
        <WatchStar cveId={row.id} testId={`priority-watch-${row.id}`} />
      </div>
      {expanded ? (
        <div className="priority-row-detail">
          <StoryStrip row={row} />
          <div className="signal-grid">
            <KevSignal row={row} />
            <EpssSignal row={row} />
            <CvssSignal row={row} />
            <SsvcSignal row={row} />
            <ExploitSignal
              references={row.exploitReferences}
              listTestId="priority-row-exploit-list"
              helpTestId="priority-row-exploit-help"
            />
            <DeltaSignal row={row} />
          </div>
          <a className="btn btn-sm" href={row.officialUrl} data-testid="priority-row-action">
            Official CVE record
          </a>
        </div>
      ) : null}
    </article>
  );
}

/** Day bucket for the due-soon groups: overdue deadlines first, explained
 * in place so a 2021 due date reads as missed-and-urgent, not stale data. */
export type DueGroup = "overdue" | "due-30d" | "due-later";

export const DUE_GROUP_LABELS: Record<DueGroup, string> = {
  overdue: "Overdue — deadline missed, most urgent first",
  "due-30d": "Due within 30 days",
  "due-later": "Due later",
};

export function dueGroupFor(dueDate: string | null, todayDay: string): DueGroup | null {
  if (dueDate === null || !/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) return null;
  if (dueDate < todayDay) return "overdue";
  const ms = Date.parse(`${todayDay}T00:00:00.000Z`);
  if (!Number.isFinite(ms)) return "due-later";
  const limit = new Date(ms + 30 * 86_400_000).toISOString().slice(0, 10);
  return dueDate <= limit ? "due-30d" : "due-later";
}

/** Partition rows into due groups, preserving server order inside each.
 * Rows without a usable due date (impossible from the server filter, kept
 * for defense) render unlabeled after the groups, never under a wrong one. */
export function groupDueRows(
  rows: readonly PriorityRowData[],
  todayDay: string,
): { groups: Array<{ group: DueGroup; rows: PriorityRowData[] }>; ungrouped: PriorityRowData[] } {
  const buckets: Record<DueGroup, PriorityRowData[]> = {
    overdue: [],
    "due-30d": [],
    "due-later": [],
  };
  const ungrouped: PriorityRowData[] = [];
  for (const row of rows) {
    const group = dueGroupFor(row.kevDueDate, todayDay);
    if (group === null) ungrouped.push(row);
    else buckets[group].push(row);
  }
  const groups: Array<{ group: DueGroup; rows: PriorityRowData[] }> = [];
  for (const group of ["overdue", "due-30d", "due-later"] as const) {
    if (buckets[group].length > 0) groups.push({ group, rows: buckets[group] });
  }
  return { groups, ungrouped };
}

export function PriorityList({
  rows,
  mode,
}: {
  rows: readonly PriorityRowData[];
  mode: PriorityMode;
}) {
  const [visible, setVisible] = useState(25);
  // One row opens by default: five expanded rows turned the list into a wall
  // of panels and blurred where one record ended and the next began.
  const [openCount, setOpenCount] = useState(1);
  const [todayDay] = useState(() => new Date().toISOString().slice(0, 10));

  useEffect(() => {
    if (window.matchMedia("(max-width: 700px)").matches) setOpenCount(1);
  }, []);

  if (rows.length === 0) {
    return (
      <div className="ledger-section" data-testid={`priority-empty-${mode}`}>
        <h2>No records in this view</h2>
        <p className="ledger-meta">
          The retained snapshot cohort has no eligible records for this list mode. Eligibility rules
          are stated above; nothing was substituted or interpolated.
        </p>
      </div>
    );
  }
  const dueSections = mode === "kev-due-soon" ? groupDueRows(rows, todayDay) : null;
  let openIndex = 0;
  const renderRow = (row: PriorityRowData): ReactNode => {
    const index = openIndex;
    openIndex += 1;
    if (index >= visible) return null;
    return <PriorityRow key={row.id} row={row} defaultOpen={index < openCount} />;
  };
  return (
    <div data-testid={`priority-list-${mode}`} className="priority-table">
      {dueSections === null ? (
        rows
          .slice(0, visible)
          .map((row, index) => (
            <PriorityRow key={row.id} row={row} defaultOpen={index < openCount} />
          ))
      ) : (
        <>
          {dueSections.groups.map((section) => (
            <section key={section.group} aria-label={DUE_GROUP_LABELS[section.group]}>
              <h3 className="due-group-heading" data-testid={`priority-due-group-${section.group}`}>
                {DUE_GROUP_LABELS[section.group]} ({section.rows.length})
              </h3>
              {section.rows.map((row) => renderRow(row))}
            </section>
          ))}
          {dueSections.ungrouped.map((row) => renderRow(row))}
        </>
      )}
      {rows.length > visible ? (
        <button
          type="button"
          className="btn btn-sm"
          onClick={() => setVisible((current) => Math.min(rows.length, current + 25))}
          style={{ marginTop: 12 }}
        >
          Show 25 more ({rows.length - visible} remaining)
        </button>
      ) : null}
    </div>
  );
}
