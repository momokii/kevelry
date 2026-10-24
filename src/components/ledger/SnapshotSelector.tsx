export type SnapshotState = "available" | "missing" | "expired" | "initial" | "stale" | "disabled" | "loading";

type SnapshotSelectorProps = {
  state: SnapshotState;
  testId: string;
};

const NOTE: Record<SnapshotState, string> = {
  available: "Retained checkpoint 2026-10-24 with ranking policy v1. Replay equals the materialized results.",
  missing: "No retained snapshot for 2026-10-18. Snapshot unavailable; current data is never substituted.",
  expired: "Checkpoint 2026-09-20 expired under the 30-day observed window. Replay refused with this reason.",
  initial: "History begins 2026-10-01. No earlier observed snapshots exist and none are fabricated.",
  stale: "Historical source is stale: EPSS score date predates the checkpoint. Values keep their stale label.",
  disabled: "Selector disabled while replay evaluates the pinned checkpoint and policy version.",
  loading: "Loading the retained checkpoint manifest.",
};

export function SnapshotSelector({ state, testId }: SnapshotSelectorProps) {
  const interactive = state === "available" || state === "stale";
  return (
    <div className="ledger-snapshot" data-testid={testId}>
      <label className="ledger-meta" htmlFor={`${testId}-select`}>
        Retained checkpoint
      </label>
      <select
        id={`${testId}-select`}
        className="ledger-snapshot-select"
        disabled={!interactive}
        aria-busy={state === "loading"}
        defaultValue={state === "available" ? "2026-10-24" : "none"}
        data-testid={`${testId}-select`}
      >
        {state === "available" ? (
          <>
            <option value="2026-10-24">2026-10-24, policy v1</option>
            <option value="2026-10-23">2026-10-23, policy v1</option>
          </>
        ) : (
          <option value="none">No selectable checkpoint</option>
        )}
      </select>
      <p className="ledger-snapshot-note" role={state === "expired" || state === "missing" ? "alert" : "status"}>
        {NOTE[state]}
      </p>
    </div>
  );
}
