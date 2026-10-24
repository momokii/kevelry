export type CompareChange = "unchanged" | "added" | "removed" | "changed" | "unknown" | "incomparable";

type CompareFieldProps = {
  change: CompareChange;
  testId: string;
};

const COPY: Record<CompareChange, { before: string; after: string; note: string }> = {
  unchanged: {
    before: "Buffer overflow in demonstration service.",
    after: "Buffer overflow in demonstration service.",
    note: "Unchanged: identical text in both snapshots.",
  },
  added: {
    before: "Field absent in the 2026-10-23 snapshot.",
    after: "KEV listed 2026-10-24.",
    note: "Added: KEV membership appeared in the new snapshot.",
  },
  removed: {
    before: "KEV listed 2026-10-20.",
    after: "Not listed in this KEV snapshot.",
    note: "Removed: absence means not in the new catalog, not proof of no exploitation.",
  },
  changed: {
    before: "Primary CNA CVSS 8.5 v4.0, vector A.",
    after: "Primary CNA CVSS 9.8 v3.1, worst CNA-provided scenario.",
    note: "Changed: source revision 9f31 to a431, observed 2026-10-24 08:00 UTC.",
  },
  unknown: {
    before: "EPSS 4.10 percent, model v4, 2026-10-17.",
    after: "EPSS unavailable for this snapshot.",
    note: "Unknown: missing current row is unknown, not zero and not interpolated.",
  },
  incomparable: {
    before: "EPSS 4.10 percent, model v3, 2026-10-17.",
    after: "EPSS 18.20 percent, model v4, 2026-10-24.",
    note: "Forecasts use different models; change is not compared.",
  },
};

export function CompareField({ change, testId }: CompareFieldProps) {
  const copy = COPY[change];
  return (
    <div className="ledger-compare" data-testid={testId}>
      <div className="ledger-compare-cell">
        <span className="ledger-compare-label">Before: 2026-10-23 snapshot</span>
        <p>{copy.before}</p>
      </div>
      <div className="ledger-compare-cell">
        <span className="ledger-compare-label">After: 2026-10-24 snapshot</span>
        <p>{copy.after}</p>
      </div>
      <p className="ledger-compare-change" data-testid={`${testId}-note`}>
        {change === "added" ? "[+] " : change === "removed" ? "[-] " : change === "changed" ? "[~] " : "[=] "}
        {copy.note}
      </p>
    </div>
  );
}
