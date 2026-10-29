"use client";

// Priority list primitives (plan todo 20; typography pass task 49).
// Presentational only: no database, no fetch, no ordering logic. The server
// component in `app/priority/page.tsx` computes every value with the priority
// services and passes rendered-ready props here. Signals render as structured
// blocks (bold key values, italic caveats, mono labels) with HelpTip
// definitions and TimeText dates; styling reuses the ledger classes from
// `app/globals.css` plus the local `PrioritySignals.module.css` grid.

import { useEffect, useState, type ReactNode } from "react";

import { HelpTip } from "../ledger/HelpTip";
import { TimeText } from "../ledger/TimeText";

import styles from "./PrioritySignals.module.css";

export type PriorityMode =
  "known-exploited" | "highest-forecast" | "new-critical" | "rising-forecast";

export const PRIORITY_MODES: readonly PriorityMode[] = [
  "known-exploited",
  "highest-forecast",
  "new-critical",
  "rising-forecast",
];

export const PRIORITY_MODE_LABELS: Record<PriorityMode, string> = {
  "known-exploited": "Known exploited",
  "highest-forecast": "Highest forecast",
  "new-critical": "New critical",
  "rising-forecast": "Rising forecast",
};

export interface PriorityRowData {
  id: string;
  title: string;
  excerpt: string | null;
  excerptTruncated: boolean;
  publishedAt: string | null;
  kevListed: boolean;
  kevDateAdded: string | null;
  epssKnown: boolean;
  epssPercent: string | null;
  epssModel: string | null;
  epssDate: string | null;
  primaryKnown: boolean;
  primaryLegacy: boolean;
  primaryAdpOnly: boolean;
  primaryVersion: string | null;
  primaryScore: string | null;
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

/** KEV membership state label. Listed keeps the exact "KEV listed" wording;
 * unlisted names the snapshot scope and never implies proof of safety. */
export function kevStateText(listed: boolean): string {
  return listed ? "KEV listed" : "Not listed in this KEV snapshot.";
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

function KevSignal({ row }: { row: PriorityRowData }) {
  return (
    <div className={styles.signal} aria-label="KEV signal">
      <div className={styles.signalHead}>
        <span className="ledger-label">KEV</span>
        <HelpTip term="KEV" testId="priority-row-kev-help">
          CISA Known Exploited Vulnerabilities catalog membership. Catalog dates mark catalog
          addition, not proven first exploitation or current attack volume.
        </HelpTip>
      </div>
      {row.kevListed ? (
        <p>
          <strong className="ledger-emphasis">{kevStateText(true)}</strong>
          {row.kevDateAdded !== null ? (
            <>
              {" on "}
              <TimeText value={row.kevDateAdded} testId="priority-row-kev-date" />
            </>
          ) : null}
        </p>
      ) : (
        <p>
          <strong className="ledger-emphasis">Not listed</strong> in this KEV snapshot.{" "}
          <em className="ledger-caveat">Absence is not proof of no exploitation.</em>
        </p>
      )}
    </div>
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
            Unscored under this view&apos;s policy; ADP-only metrics are retained for inspection,
            never promoted.
          </em>
        </p>
      ) : (
        <p>
          <em className="ledger-caveat">Unscored under this view&apos;s policy.</em>
        </p>
      )}
    </div>
  );
}

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
          <span className="priority-chevron" aria-hidden="true">
            {expanded ? "−" : "+"}
          </span>
          <span className="sr-only">{summaryText(row)}</span>
        </span>
      </button>
      {expanded ? (
        <div className="priority-row-detail">
          <div className="signal-grid">
            <KevSignal row={row} />
            <EpssSignal row={row} />
            <CvssSignal row={row} />
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

export function PriorityList({
  rows,
  mode,
}: {
  rows: readonly PriorityRowData[];
  mode: PriorityMode;
}) {
  const [visible, setVisible] = useState(25);
  const [openCount, setOpenCount] = useState(5);

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
  return (
    <div data-testid={`priority-list-${mode}`} className="priority-table">
      {rows.slice(0, visible).map((row, index) => (
        <PriorityRow key={row.id} row={row} defaultOpen={index < openCount} />
      ))}
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
