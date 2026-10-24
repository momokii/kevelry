// Priority list primitives (plan todo 20). Presentational only: no database,
// no fetch, no ordering logic. The server component in `app/priority/page.tsx`
// computes every value with the priority services and passes rendered-ready
// props here. All styling reuses the ledger classes from `app/globals.css`
// (tokens in DESIGN.md sections 2-4); no color literals, no ad-hoc spacing.

export type PriorityMode = "known-exploited" | "highest-forecast" | "new-critical" | "rising-forecast";

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

export function PriorityModeNav({ current }: { current: PriorityMode }) {
  return (
    <nav className="ledger-filter-group" aria-label="Priority list modes" data-testid="priority-mode-nav">
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

export function PriorityOrdering({ mode, body }: { mode: PriorityMode; body: string }) {
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
    <div
      className="ledger-ordering"
      data-testid={`priority-ordering-${mode}`}
      tabIndex={0}
      aria-label={`Ordering policy: ${headings[mode]}`}
    >
      <strong>{headings[mode]}</strong>
      <span className="ledger-meta">{body}</span>
    </div>
  );
}

export function PriorityEvidence({
  stale,
  detail,
  testId,
}: {
  stale: boolean;
  detail: string;
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

function signalLine(row: PriorityRowData): string {
  const parts: string[] = [];
  if (row.kevListed) {
    parts.push(row.kevDateAdded !== null ? `KEV listed ${row.kevDateAdded}.` : "KEV listed.");
  } else {
    parts.push("Not listed in this KEV snapshot.");
  }
  if (row.epssKnown && row.epssPercent !== null) {
    const model = row.epssModel !== null ? `, model ${row.epssModel}` : "";
    const date = row.epssDate !== null ? ` dated ${row.epssDate}` : "";
    parts.push(`EPSS ${row.epssPercent} percent${model}${date}.`);
  } else {
    parts.push("EPSS unavailable for this snapshot.");
  }
  if (row.primaryKnown && row.primaryVersion !== null && row.primaryScore !== null) {
    parts.push(`Primary CNA CVSS ${row.primaryScore} v${row.primaryVersion}.`);
  } else if (row.primaryLegacy && row.primaryVersion !== null && row.primaryScore !== null) {
    parts.push(`Legacy-scored CNA CVSS ${row.primaryScore} v${row.primaryVersion}; not critical.`);
  } else if (row.primaryAdpOnly) {
    parts.push("Unscored under this view's policy; ADP-only metrics retained for inspection.");
  } else {
    parts.push("Unscored under this view's policy.");
  }
  if (row.deltaPp !== null && row.deltaPreviousDate !== null && row.epssDate !== null) {
    const model = row.epssModel !== null ? `, same model ${row.epssModel}` : "";
    parts.push(
      `Forecast movement: +${row.deltaPp} percentage points since ${row.deltaPreviousDate}${model}.`,
    );
  }
  return parts.join(" ");
}

export function PriorityRow({ row }: { row: PriorityRowData }) {
  return (
    <article className="ledger-row" data-testid="priority-row" data-cve-id={row.id}>
      <span className="ledger-row-id" data-testid="priority-row-id">
        {row.id}
      </span>
      <p className="ledger-row-title" data-testid="priority-row-title">
        {row.title}
      </p>
      <p className="ledger-row-title ledger-meta" data-testid="priority-row-excerpt">
        {row.excerpt ?? "Description not supplied"}
        {row.excerptTruncated ? " [truncated]" : ""}
      </p>
      <p className="ledger-row-signals" data-testid="priority-row-signals">
        {signalLine(row)}
      </p>
      <a className="ledger-row-action" href={row.officialUrl} data-testid="priority-row-action">
        Official CVE record
      </a>
    </article>
  );
}

export function PriorityList({ rows, mode }: { rows: readonly PriorityRowData[]; mode: PriorityMode }) {
  if (rows.length === 0) {
    return (
      <div className="ledger-section" data-testid={`priority-empty-${mode}`}>
        <h2>No records in this view</h2>
        <p className="ledger-meta">
          The retained snapshot cohort has no eligible records for this list mode. Eligibility rules are stated
          above; nothing was substituted or interpolated.
        </p>
      </div>
    );
  }
  return (
    <div data-testid={`priority-list-${mode}`}>
      {rows.map((row) => (
        <PriorityRow key={row.id} row={row} />
      ))}
    </div>
  );
}
