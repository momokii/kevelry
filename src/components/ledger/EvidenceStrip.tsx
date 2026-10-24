export type EvidenceState = "default" | "stale" | "failed" | "missing" | "loading";

type EvidenceStripProps = {
  state: EvidenceState;
  testId: string;
};

const COPY: Record<EvidenceState, { symbol: string; label: string; detail: string }> = {
  default: {
    symbol: "=",
    label: "Current",
    detail: "CVE List V5 rev 9f31, observed 2026-10-24 08:00 UTC. EPSS model v4 dated 2026-10-24. KEV catalog dated 2026-10-23.",
  },
  stale: {
    symbol: "~",
    label: "Stale",
    detail: "EPSS score date is older than 2 UTC calendar days. Dated values retained with this label.",
  },
  failed: {
    symbol: "!",
    label: "Source failed",
    detail: "KEV refresh failed at 2026-10-24 09:12 UTC. Last-known-good membership shown with this warning.",
  },
  missing: {
    symbol: "?",
    label: "Missing",
    detail: "No retained snapshot for 2026-10-18. Snapshot unavailable; nothing is interpolated.",
  },
  loading: {
    symbol: "...",
    label: "Loading",
    detail: "Checking source freshness against the retained manifest.",
  },
};

export function EvidenceStrip({ state, testId }: EvidenceStripProps) {
  const copy = COPY[state];
  return (
    <div className="ledger-evidence" data-testid={testId} aria-busy={state === "loading"}>
      <span className="ledger-evidence-symbol" aria-hidden="true">
        {copy.symbol}
      </span>
      <span className="ledger-evidence-state">{copy.label}</span>
      <span data-testid={`${testId}-detail`}>{copy.detail}</span>
    </div>
  );
}
