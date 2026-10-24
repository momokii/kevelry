export type ChartState = "default" | "loading" | "empty" | "unknown" | "correction" | "error";

type ChartViewProps = {
  state: ChartState;
  testId: string;
};

const ROWS = [
  { bucket: "2026-10-18", count: "41 published" },
  { bucket: "2026-10-19", count: "58 published" },
  { bucket: "2026-10-20", count: "37 published" },
  { bucket: "Unknown date", count: "6 in explicit bucket, excluded from dated bars" },
] as const;

export function ChartView({ state, testId }: ChartViewProps) {
  if (state === "loading") {
    return (
      <div className="ledger-skeleton" role="status" data-testid={testId}>
        Loading publication chart. Axes, units, and coverage will appear with the data.
      </div>
    );
  }
  if (state === "empty") {
    return (
      <div className="ledger-skeleton" data-testid={testId}>
        Empty interval: no published records in this UTC range. This is an honest empty state, not a zero baseline.
      </div>
    );
  }
  if (state === "error") {
    return (
      <div className="ledger-skeleton" role="alert" data-testid={testId}>
        Chart failed to render from the retained snapshot. The data table below is unavailable; retry keeps
        last-known-good content.
      </div>
    );
  }
  return (
    <div data-testid={testId}>
      <div className="ledger-chart-bars" aria-hidden="true" data-testid={`${testId}-bars`}>
        <div className="ledger-chart-bar" style={{ height: "48px" }} />
        <div className="ledger-chart-bar" style={{ height: "72px" }} />
        <div className="ledger-chart-bar" style={{ height: "40px" }} />
        <div className="ledger-chart-bar ledger-chart-bar-secondary" style={{ height: "16px" }} />
      </div>
      <table className="ledger-chart-table" data-testid={`${testId}-table`}>
        <caption className="ledger-meta">
          {state === "unknown"
            ? "Publication counts by UTC calendar day, with the unknown-date bucket listed separately."
            : state === "correction"
              ? "Corrections applied: one record moved from 2026-10-19 to 2026-10-20 after an upstream correction."
              : "Publication counts by UTC calendar day. Unknown dates are excluded from dated bars."}
        </caption>
        <thead>
          <tr>
            <th scope="col">UTC bucket</th>
            <th scope="col">Records</th>
          </tr>
        </thead>
        <tbody>
          {ROWS.map((row) => (
            <tr key={row.bucket}>
              <th scope="row">{row.bucket}</th>
              <td>{row.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {state === "correction" ? (
        <p className="ledger-meta" data-testid={`${testId}-note`}>
          Correction note: totals changed because the source corrected a date, not because history was rewritten.
        </p>
      ) : null}
    </div>
  );
}
