import { TimeText } from "@/components/ledger/TimeText";
import type { Provenance, SourceProvenance } from "@/app/api/v1/_lib/shared";

type SourceState = "current" | "stale" | "failed" | "missing";

function stateOf(source: SourceProvenance): SourceState {
  if (source.error !== null) return "failed";
  if (source.lastCheckedAt === null && source.lastAcceptedAt === null) return "missing";
  if (source.stale) return "stale";
  return "current";
}

function symbolFor(state: SourceState): string {
  if (state === "failed") return "!";
  if (state === "missing") return "?";
  if (state === "stale") return "~";
  return "=";
}

function labelFor(state: SourceState): string {
  if (state === "failed") return "Source failed";
  if (state === "missing") return "Missing";
  if (state === "stale") return "Stale";
  return "Current";
}

function dotClass(state: SourceState): string {
  if (state === "failed") return "status-dot is-failed";
  if (state === "stale") return "status-dot is-stale";
  if (state === "missing") return "status-dot";
  return "status-dot";
}

function meaningOf(key: "cve" | "kev" | "epss", state: SourceState): string {
  if (state === "failed") return "Last accepted snapshot is still served.";
  if (state === "missing") return "No snapshot accepted yet; dependent counts are empty.";
  if (key === "epss") return "Forecasts stay dated; older scores are never relabeled current.";
  if (key === "kev") return "Recent catalog additions may be missing from this snapshot.";
  return "Recent CVEs may be missing from this snapshot.";
}

function verdict(entries: Array<{ name: string; state: SourceState }>): string {
  const failed = entries.filter((entry) => entry.state === "failed");
  const current = entries.filter((entry) => entry.state === "current").length;
  if (failed.length > 0) {
    return `${failed.map((entry) => entry.name).join(" and ")} refresh failed; last accepted data is still shown.`;
  }
  if (current === entries.length) return "All sources current.";
  const rest = entries
    .filter((entry) => entry.state !== "current")
    .map((entry) => `${entry.name} ${entry.state}`)
    .join(", ");
  return `${current} of ${entries.length} current: ${rest}.`;
}

export function FreshnessPanel({ provenance }: { provenance: Provenance }) {
  const entries = [
    { key: "cve" as const, name: "CVE List V5", source: provenance.sources.cve },
    { key: "kev" as const, name: "CISA KEV", source: provenance.sources.kev },
    { key: "epss" as const, name: "FIRST EPSS", source: provenance.sources.epss },
  ];
  const states = entries.map((entry) => ({ name: entry.name, state: stateOf(entry.source) }));
  return (
    <div data-testid="overview-freshness">
      <p className="takeaway" data-testid="overview-freshness-verdict">
        <strong>{verdict(states)}</strong> Freshness explains how old the numbers are; it never
        changes the numbers themselves.
      </p>
      <div className="freshness-list">
        {entries.map((entry) => {
          const state = stateOf(entry.source);
          return (
            <div
              key={entry.key}
              className="freshness-row"
              data-testid={`overview-freshness-${entry.key}`}
            >
              <span className={dotClass(state)} aria-hidden="true" />
              <span className="freshness-name">{entry.name}</span>
              <span className="freshness-state">
                {symbolFor(state)} {labelFor(state)}
              </span>
              <span className="freshness-detail">
                checked{" "}
                <TimeText
                  value={entry.source.lastCheckedAt}
                  showRelative
                  testId={`overview-freshness-${entry.key}-checked`}
                />{" "}
                · accepted{" "}
                <TimeText
                  value={entry.source.lastAcceptedAt}
                  showRelative
                  testId={`overview-freshness-${entry.key}-accepted`}
                />
              </span>
            </div>
          );
        })}
      </div>
      <p className="chart-note">
        {states
          .map(
            (entry) =>
              `${entry.name}: ${meaningOf(entry.name === "CVE List V5" ? "cve" : entry.name === "CISA KEV" ? "kev" : "epss", entry.state)}`,
          )
          .join(" ")}
      </p>
      {entries.map((entry) =>
        entry.source.error !== null ? (
          <p
            key={`${entry.key}-error`}
            className="chart-note"
            data-testid={`overview-freshness-${entry.key}-detail`}
          >
            Refresh failed: {entry.source.error}
          </p>
        ) : null,
      )}
      <div className="panel-foot" style={{ paddingLeft: 0, paddingRight: 0 }}>
        <a href="/methodology#methodology-section-status">Full source status and thresholds</a>
      </div>
    </div>
  );
}
