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
  "known-exploited" | "highest-forecast" | "new-critical" | "rising-forecast" | "kev-due-soon";

export const PRIORITY_MODES: readonly PriorityMode[] = [
  "known-exploited",
  "highest-forecast",
  "new-critical",
  "rising-forecast",
  "kev-due-soon",
];

export const PRIORITY_MODE_LABELS: Record<PriorityMode, string> = {
  "known-exploited": "Known exploited",
  "highest-forecast": "Highest forecast",
  "new-critical": "New critical",
  "rising-forecast": "Rising forecast",
  "kev-due-soon": "KEV due soon",
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
  kevRansomwareKnown: boolean | null;
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
    "kev-due-soon":
      "KEV due soon: KEV members with a valid catalog remediation due date. Order due date ascending (overdue first, no upper cutoff), then CVE ID ASCII ascending.",
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
          {row.kevDueDate !== null ? (
            <>
              {"; remediation due "}
              <TimeText value={row.kevDueDate} testId="priority-row-kev-due" />
            </>
          ) : null}
          {row.kevRansomwareKnown === true ? (
            <>
              {" · "}
              <strong className="ledger-emphasis">known ransomware use</strong>
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

/** Dated EPSS trend sparkline: linear 0..1 probability plot, oldest left.
 * Display geometry only (pixel positions); never a comparison or a score. */
function EpssTrend({ points }: { points: EpssTrendPoint[] }) {
  const values = points.map((point) => {
    const parsed = Number(point.epss);
    return Number.isFinite(parsed) ? Math.min(1, Math.max(0, parsed)) : null;
  });
  if (values.length < 2 || values.some((value) => value === null)) return null;
  const nums = values as number[];
  const coords = nums.map((value, index) => {
    const x = points.length === 1 ? 50 : (index / (points.length - 1)) * 100;
    return `${x.toFixed(1)},${(34 - value * 32).toFixed(1)}`;
  });
  const first = points[0];
  const last = points[points.length - 1];
  if (first === undefined || last === undefined) return null;
  const lastX = points.length === 1 ? 50 : 100;
  const lastY = 34 - (nums[nums.length - 1] ?? 0) * 32;
  return (
    <figure style={{ margin: 0 }}>
      <svg
        className={styles.trend}
        viewBox="0 0 100 36"
        preserveAspectRatio="none"
        role="img"
        aria-label={`EPSS trend over ${points.length} dated observations, ${first.scoreDate} to ${last.scoreDate}.`}
        data-testid="priority-row-epss-trend"
      >
        <polyline
          points={coords.join(" ")}
          fill="none"
          stroke="currentColor"
          strokeWidth={1.5}
          vectorEffect="non-scaling-stroke"
        />
        <circle cx={lastX} cy={lastY} r={2.5} fill="currentColor" />
      </svg>
      <figcaption className={styles.trendCaption}>
        {points.length} dated observations, {first.scoreDate} to {last.scoreDate}
        {last.modelVersion !== "" ? ` · model ${last.modelVersion}` : ""}; latest point marked.
      </figcaption>
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
  const [openCount, setOpenCount] = useState(5);
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
