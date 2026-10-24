import type { Provenance, SourceProvenance } from "@/app/api/v1/_lib/shared";

type SourceFreshnessProps = {
  provenance: Provenance;
};

interface SourceLine {
  key: string;
  name: string;
  detail: string;
  state: SourceProvenance;
}

function describeState(state: SourceProvenance): { symbol: string; label: string } {
  if (state.error !== null) return { symbol: "!", label: "Source failed" };
  if (state.lastCheckedAt === null && state.lastAcceptedAt === null) {
    return { symbol: "?", label: "Missing" };
  }
  if (state.stale) return { symbol: "~", label: "Stale" };
  return { symbol: "=", label: "Current" };
}

function describeSource(key: string, state: SourceProvenance): string {
  const checked = state.lastCheckedAt ?? "not recorded";
  const accepted = state.lastAcceptedAt ?? "not recorded";
  if (key === "cve") {
    return `CVE List V5 revision ${state.revision ?? "unknown"}, last accepted ${accepted}, last checked ${checked}.`;
  }
  if (key === "kev") {
    return `KEV catalog dated ${state.catalogVersion ?? "unknown"}, last accepted ${accepted}, last checked ${checked}.`;
  }
  return (
    `EPSS score date ${state.scoreDate ?? "unknown"}, model ${state.modelVersion ?? "unknown"}, ` +
    `last accepted ${accepted}, last checked ${checked}.`
  );
}

export function SourceFreshness({ provenance }: SourceFreshnessProps) {
  const lines: SourceLine[] = [
    {
      key: "cve",
      name: "CVE List V5",
      detail: describeSource("cve", provenance.sources.cve),
      state: provenance.sources.cve,
    },
    {
      key: "kev",
      name: "CISA KEV",
      detail: describeSource("kev", provenance.sources.kev),
      state: provenance.sources.kev,
    },
    {
      key: "epss",
      name: "FIRST EPSS",
      detail: describeSource("epss", provenance.sources.epss),
      state: provenance.sources.epss,
    },
  ];
  return (
    <div data-testid="overview-freshness">
      {lines.map((line) => {
        const status = describeState(line.state);
        return (
          <div
            key={line.key}
            className="ledger-evidence"
            data-testid={`overview-freshness-${line.key}`}
          >
            <span className="ledger-evidence-symbol" aria-hidden="true">
              {status.symbol}
            </span>
            <span className="ledger-evidence-state">
              {line.name}: {status.label}
            </span>
            <span data-testid={`overview-freshness-${line.key}-detail`}>
              {line.detail}
              {line.state.error !== null ? ` Refresh failed: ${line.state.error}` : null}
            </span>
          </div>
        );
      })}
    </div>
  );
}
