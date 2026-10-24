export type OrderingState = "default" | "tie" | "missing" | "coverage" | "stale";

type OrderingExplanationProps = {
  state: OrderingState;
  testId: string;
};

const COPY: Record<OrderingState, { heading: string; body: string }> = {
  default: {
    heading: "Highest forecast: raw EPSS probability descending, publication descending, ID ascending.",
    body: "Display shows rounded percentages; ordering uses raw source decimals. Score date and model version are shown per value.",
  },
  tie: {
    heading: "Tie rule: equal raw probabilities fall back to publication date, then CVE ID ASCII.",
    body: "Display rounding never decides a tie. Two records showing 12.34 percent keep their raw-value order.",
  },
  missing: {
    heading: "Missing values: unknown EPSS sorts after every known value, including zero.",
    body: "Unknown is a labeled state, not a zero. Unscored CVEs are ineligible for the new-critical view.",
  },
  coverage: {
    heading: "Coverage: 5,214 of 5,301 published records carry a current EPSS row.",
    body: "The denominator is the retained snapshot cohort. Join gaps are reported, never silently dropped.",
  },
  stale: {
    heading: "Stale policy: EPSS score date is older than 2 UTC calendar days.",
    body: "Dated values are retained with this label. They are never relabeled as current-day forecasts.",
  },
};

export function OrderingExplanation({ state, testId }: OrderingExplanationProps) {
  const copy = COPY[state];
  return (
    <div className="ledger-ordering" data-testid={testId} tabIndex={0} aria-label={`Ordering policy: ${copy.heading}`}>
      <strong>{copy.heading}</strong>
      <span className="ledger-meta">{copy.body}</span>
    </div>
  );
}
