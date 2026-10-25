import { TimeText } from "@/components/ledger/TimeText";
import type { Provenance, SourceProvenance } from "@/app/api/v1/_lib/shared";

type SourceFreshnessProps = {
  provenance: Provenance;
};

type SourceState = "current" | "stale" | "failed" | "missing";

interface SourceLine {
  key: "cve" | "kev" | "epss";
  name: string;
  state: SourceProvenance;
}

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

function shortLabelFor(state: SourceState): string {
  if (state === "failed") return "Source failed";
  if (state === "missing") return "Missing";
  if (state === "stale") return "Stale";
  return "Current";
}

function plainStateLine(name: string, state: SourceState): string {
  if (state === "failed") return `${name}: last refresh failed, showing the last accepted data.`;
  if (state === "missing")
    return `${name}: no snapshot accepted yet, related counts are empty rather than guessed.`;
  if (state === "stale")
    return `${name}: working from dated data; values are retained as-is and nothing is relabeled as current.`;
  return `${name}: up to date; counts on this page include its latest accepted update.`;
}

function meaningLine(key: SourceLine["key"], state: SourceState): string {
  if (state === "failed")
    return "The failed refresh changed nothing: charts and lists still show the last accepted snapshot.";
  if (state === "missing")
    return "Until the first snapshot lands, lists that need this source stay explicitly empty.";
  if (key === "epss")
    return "EPSS values are a dated forecast for the score date below; older scores stay visible but are never treated as current.";
  if (key === "kev")
    return "KEV membership only grows when the catalog adds entries; staleness means recent additions may be missing.";
  return "Publication counts only move when a new revision is accepted; staleness means recent CVEs may be missing.";
}

function technicalLine(key: SourceLine["key"], source: SourceProvenance): string {
  const checked = source.lastCheckedAt ?? "not recorded";
  const accepted = source.lastAcceptedAt ?? "not recorded";
  if (key === "cve") {
    return `CVE List V5 revision ${source.revision ?? "unknown"}, last accepted ${accepted}, last checked ${checked}.`;
  }
  if (key === "kev") {
    return `KEV catalog dated ${source.catalogVersion ?? "unknown"}, last accepted ${accepted}, last checked ${checked}.`;
  }
  return (
    `EPSS score date ${source.scoreDate ?? "unknown"}, model ${source.modelVersion ?? "unknown"}, ` +
    `last accepted ${accepted}, last checked ${checked}.`
  );
}

function verdict(sources: Array<{ name: string; state: SourceState }>): string {
  const failed = sources.filter((entry) => entry.state === "failed");
  const current = sources.filter((entry) => entry.state === "current").length;
  if (failed.length > 0) {
    const names = failed.map((entry) => entry.name).join(" and ");
    return `${names} refresh failed; ${current} of ${sources.length} current. Last accepted data is still shown.`;
  }
  if (current === sources.length) return "All sources current.";
  const notCurrent = sources
    .filter((entry) => entry.state !== "current")
    .map((entry) => `${entry.name} ${entry.state}`)
    .join(", ");
  return `${current} of ${sources.length} current: ${notCurrent}.`;
}

export function SourceFreshness({ provenance }: SourceFreshnessProps) {
  const lines: SourceLine[] = [
    { key: "cve", name: "CVE List V5", state: provenance.sources.cve },
    { key: "kev", name: "CISA KEV", state: provenance.sources.kev },
    { key: "epss", name: "FIRST EPSS", state: provenance.sources.epss },
  ];
  const states = lines.map((line) => ({ name: line.name, state: stateOf(line.state) }));
  return (
    <div data-testid="overview-freshness">
      <p className="ledger-meta" data-testid="overview-freshness-verdict">
        <span className="ledger-emphasis">{verdict(states)}</span> Freshness tells you how old the
        numbers on this page are; it never changes the numbers themselves.
      </p>
      {lines.map((line) => {
        const state = stateOf(line.state);
        return (
          <div
            key={line.key}
            className="ledger-evidence"
            data-testid={`overview-freshness-${line.key}`}
          >
            <span className="ledger-evidence-symbol" aria-hidden="true">
              {symbolFor(state)}
            </span>
            <span className="ledger-evidence-state">
              {line.name}: {shortLabelFor(state)}
            </span>
            {line.state.error !== null ? (
              <p
                className="ledger-search-error"
                data-testid={`overview-freshness-${line.key}-detail`}
              >
                Refresh failed: {line.state.error}
              </p>
            ) : null}
            <p className="ledger-meta" data-testid={`overview-freshness-${line.key}-plain`}>
              {plainStateLine(line.name, state)}{" "}
              <span className="ledger-caveat">{meaningLine(line.key, state)}</span>
            </p>
            <p className="ledger-meta" data-testid={`overview-freshness-${line.key}-checked`}>
              Last checked{" "}
              <TimeText
                value={line.state.lastCheckedAt}
                showRelative
                testId={`overview-freshness-${line.key}-checked-time`}
              />
              {", last accepted "}
              <TimeText
                value={line.state.lastAcceptedAt}
                showRelative
                testId={`overview-freshness-${line.key}-accepted-time`}
              />
              .
            </p>
            <details data-testid={`overview-freshness-${line.key}-technical`}>
              <summary>Technical detail</summary>
              <p
                className="ledger-meta"
                data-testid={`overview-freshness-${line.key}-technical-line`}
              >
                {technicalLine(line.key, line.state)}
                {line.key === "cve"
                  ? ` Source revision: ${line.state.revision ?? "unknown"}.`
                  : null}
                {line.key === "kev"
                  ? ` Catalog version: ${line.state.catalogVersion ?? "unknown"}.`
                  : null}
                {line.key === "epss"
                  ? ` Score date: ${line.state.scoreDate ?? "unknown"}; model: ${line.state.modelVersion ?? "unknown"}.`
                  : null}{" "}
                Exact check time:{" "}
                <TimeText
                  value={line.state.lastCheckedAt}
                  testId={`overview-freshness-${line.key}-exact-checked`}
                />
                {"; exact accept time: "}
                <TimeText
                  value={line.state.lastAcceptedAt}
                  testId={`overview-freshness-${line.key}-exact-accepted`}
                />
                {line.state.error !== null ? ` Refresh error: ${line.state.error}` : null}
              </p>
            </details>
          </div>
        );
      })}
      <div className="ledger-meta" data-testid="overview-freshness-legend">
        <p>
          <span className="ledger-label">Legend</span>: = means current (freshly accepted), ~ means
          stale (dated but retained), ! means refresh failed (last accepted data shown), ? means
          missing (no snapshot accepted yet).
        </p>
        <p>
          Thresholds: CVE List V5 and CISA KEV go stale 3 hours after the last accepted update;
          FIRST EPSS goes stale when its score date is more than 2 days old. Symbols always come
          with these words; color is never the only signal.
        </p>
      </div>
    </div>
  );
}
