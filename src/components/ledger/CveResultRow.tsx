export type CveRowVariant = "default" | "long" | "missing" | "unscored" | "unknown-epss" | "rejected";

type CveResultRowProps = {
  variant: CveRowVariant;
  testId: string;
};

const LONG_URL = "https://www.cve.org/CVERecord?id=CVE-2026-1234 attendee demonstration with an unbroken reference token ";
const LONG_RUN = "a".repeat(120);

const COPY: Record<CveRowVariant, { id: string; title: string; signals: string }> = {
  default: {
    id: "CVE-2026-1234",
    title: "Supplied CNA title: buffer overflow in demonstration service.",
    signals: "KEV listed 2026-10-20. EPSS 12.34 percent, model v4 dated 2026-10-24. Primary CNA CVSS 9.8 v3.1.",
  },
  long: {
    id: "CVE-2026-1234",
    title:
      "A very long supplied title that must wrap across lines without breaking the row grid or pushing the official-record action off the readable measure of the page.",
    signals: "KEV listed 2026-10-20. EPSS 12.34 percent, model v4 dated 2026-10-24. Primary CNA CVSS 9.8 v3.1.",
  },
  missing: {
    id: "CVE-2026-2234",
    title: "Description not supplied",
    signals: "Not listed in this KEV snapshot. EPSS 2.10 percent, model v4 dated 2026-10-24.",
  },
  unscored: {
    id: "CVE-2026-3234",
    title: "Supplied description excerpt renders here as plain text.",
    signals: "Unscored under this view's policy. Secondary metrics retained for inspection.",
  },
  "unknown-epss": {
    id: "CVE-2026-4234",
    title: "Supplied description excerpt renders here as plain text.",
    signals: "EPSS unavailable for this snapshot, not 0 percent.",
  },
  rejected: {
    id: "CVE-2026-5234",
    title: "Rejected record: this entry is not a vulnerability record.",
    signals: "Rejected records leave ordinary lists and counts.",
  },
};

export function CveResultRow({ variant, testId }: CveResultRowProps) {
  const copy = COPY[variant];
  return (
    <article className="ledger-row" data-testid={testId}>
      <span className="ledger-row-id" data-testid={`${testId}-id`}>
        {copy.id}
      </span>
      <p className="ledger-row-title" data-testid={`${testId}-title`}>
        {copy.title}
      </p>
      {variant === "long" ? (
        <p className="ledger-row-title" data-testid={`${testId}-stress`}>
          {LONG_URL}
          {LONG_RUN}
        </p>
      ) : null}
      <p className="ledger-row-signals" data-testid={`${testId}-signals`}>
        {copy.signals}
      </p>
      <a className="ledger-row-action" href="https://www.cve.org/CVERecord?id=CVE-2026-1234" data-testid={`${testId}-action`}>
        Official CVE record
      </a>
    </article>
  );
}
