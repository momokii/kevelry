import type { RadarItemSnapshot, StoredRadarCheckpoint } from "@/lib/radar";
import { TimeText } from "@/components/ledger/TimeText";
import { officialCveLink } from "@/lib/search";

export interface ReplayCheckpointOption {
  checkpointDate: string;
  policyVersion: string;
  expired: boolean;
}

export interface ReplaySelection {
  selectedDate: string;
  expectedModel: string | undefined;
  retainedFrom: string;
  retainedTo: string;
  launchDay: string;
  checkpoints: ReplayCheckpointOption[];
}

function signalText(item: RadarItemSnapshot, pins: StoredRadarCheckpoint["sourcePins"]): string {
  const parts: string[] = [];
  if (item.kevMember) {
    parts.push(`KEV listed ${item.dateAdded ?? "date unknown"}.`);
  } else {
    parts.push("Not listed in this KEV snapshot.");
  }
  if (item.epss === null) {
    parts.push("EPSS unavailable for this snapshot.");
  } else {
    const percent = (Number(item.epss) * 100).toFixed(2);
    parts.push(
      `EPSS ${percent} percent, model ${item.epssModel ?? pins.epssModelVersion} dated ${pins.epssScoreDate}.`,
    );
  }
  if (item.primaryVersion === null || item.primaryBaseScore === null) {
    parts.push("Unscored under this view's policy.");
  } else {
    parts.push(`Primary CNA CVSS ${item.primaryBaseScore} version ${item.primaryVersion}.`);
  }
  if (item.publishedAt === null) {
    parts.push("Publication date not retained.");
  } else {
    parts.push(`Published ${item.publishedAt}.`);
  }
  return parts.join(" ");
}

const REPLAY_NAV = [
  { label: "Overview", href: "/" },
  { label: "Search", href: "/explore" },
  { label: "Priority", href: "/priority" },
  { label: "Radar", href: "/radar" },
  { label: "Method", href: "/methodology" },
] as const;

export function ReplayMasthead({ bannerText }: { bannerText: string }) {
  return (
    <header className="ledger-masthead" data-testid="replay-masthead">
      <span className="ledger-brand">Evidence Ledger</span>
      <nav className="ledger-nav" aria-label="Primary">
        {REPLAY_NAV.map((item) => (
          <a key={item.label} className="ledger-nav-link" href={item.href}>
            {item.label}
          </a>
        ))}
        <span className="ledger-nav-link ledger-nav-link-current" aria-current="page">
          Replay (current)
        </span>
      </nav>
      <p className="ledger-historical-banner" data-testid="replay-banner">
        {bannerText}
      </p>
    </header>
  );
}

export function ReplaySelector({ selection }: { selection: ReplaySelection }) {
  return (
    <section
      className="ledger-section"
      aria-labelledby="replay-selector-heading"
      data-testid="replay-selector"
    >
      <h2 id="replay-selector-heading">Retained checkpoint</h2>
      <form className="ledger-search" method="get" action="/replay">
        <label className="ledger-meta" htmlFor="replay-selector-select">
          Checkpoint date
        </label>
        <select
          id="replay-selector-select"
          name="date"
          className="ledger-snapshot-select"
          defaultValue={selection.selectedDate}
          data-testid="replay-selector-select"
        >
          {selection.checkpoints.map((option) => (
            <option
              key={option.checkpointDate}
              value={option.checkpointDate}
              data-testid={`replay-option-${option.checkpointDate}`}
            >
              {option.expired
                ? `${option.checkpointDate} (expired)`
                : `${option.checkpointDate}, policy ${option.policyVersion}`}
            </option>
          ))}
        </select>
        <label className="ledger-meta" htmlFor="replay-selector-model">
          Expected forecast model (optional)
        </label>
        <input
          id="replay-selector-model"
          name="model"
          className="ledger-search-input"
          defaultValue={selection.expectedModel ?? ""}
          placeholder="Leave empty to replay without a model check"
          data-testid="replay-selector-model"
        />
        <button type="submit" className="ledger-search-button" data-testid="replay-selector-submit">
          Show retained snapshot
        </button>
      </form>
      <p className="ledger-snapshot-note" data-testid="replay-selector-note">
        {`Retained checkpoints ${selection.retainedFrom} to ${selection.retainedTo}. History begins ${selection.launchDay}. Missing days are ineligible, never interpolated.`}
      </p>
    </section>
  );
}

const VIEW_COPY: ReadonlyArray<{
  key: "defaultPriority" | "knownExploited" | "highestForecast" | "newCritical" | "risingForecast";
  slug: string;
  heading: string;
  explainer: string;
}> = [
  {
    key: "defaultPriority",
    slug: "default-priority",
    heading: "Default priority, as retained",
    explainer:
      "KEV members first, then known EPSS by raw probability, then publication recency, then CVE ID. No composite score.",
  },
  {
    key: "knownExploited",
    slug: "known-exploited",
    heading: "Known exploited, as retained",
    explainer:
      "KEV members in the retained manifest, ordered by catalog date added descending, then CVE ID.",
  },
  {
    key: "highestForecast",
    slug: "highest-forecast",
    heading: "Highest forecast, as retained",
    explainer:
      "Known retained EPSS only, raw probability descending. Display shows rounded percentages.",
  },
  {
    key: "newCritical",
    slug: "new-critical",
    heading: "New critical, as retained",
    explainer:
      "Retained PUBLISHED records in the window with a modern primary CNA score of 9.0 or higher.",
  },
  {
    key: "risingForecast",
    slug: "rising-forecast",
    heading: "Rising forecast, as retained",
    explainer: "Retained same-model positive moves against the previous retained score date.",
  },
];

export function ReplayLists({ manifest }: { manifest: StoredRadarCheckpoint }) {
  return (
    <section
      className="ledger-section"
      aria-labelledby="replay-lists-heading"
      data-testid="replay-lists"
    >
      <h2 id="replay-lists-heading">
        {`Replayed lists, ranking policy ${manifest.policyVersion}`}
      </h2>
      <p className="ledger-meta" data-testid="replay-lists-note">
        Checkpoint {manifest.checkpointDate} observed{" "}
        <TimeText value={manifest.observedAt} testId="replay-observed-at" />. Source pins: CVE
        revision {manifest.sourcePins.cveRevision}, KEV catalog {manifest.sourcePins.kevCatalogDate}
        , EPSS {manifest.sourcePins.epssScoreDate} model {manifest.sourcePins.epssModelVersion}.
        Every value below is a retained observation.
      </p>
      {VIEW_COPY.map((view) => {
        const ids = manifest.views[view.key];
        return (
          <section
            key={view.key}
            aria-labelledby={`replay-view-${view.slug}-heading`}
            data-testid={`replay-view-${view.slug}`}
          >
            <h3 id={`replay-view-${view.slug}-heading`}>{view.heading}</h3>
            <p className="ledger-meta" data-testid={`replay-view-${view.slug}-explainer`}>
              {view.explainer}
            </p>
            {ids.length === 0 ? (
              <p className="ledger-meta" data-testid={`replay-view-${view.slug}-empty`}>
                No entries in this retained view.
              </p>
            ) : (
              ids.map((cveId) => {
                const item = manifest.items[cveId];
                if (item === undefined) return null;
                return (
                  <article className="ledger-row" key={cveId} data-testid={`replay-item-${cveId}`}>
                    <span className="ledger-row-id" data-testid={`replay-item-${cveId}-id`}>
                      {cveId}
                    </span>
                    <p className="ledger-row-signals" data-testid={`replay-item-${cveId}-signals`}>
                      {signalText(item, manifest.sourcePins)}
                    </p>
                    <a
                      className="ledger-row-action"
                      href={officialCveLink(cveId)}
                      data-testid={`replay-item-${cveId}-action`}
                    >
                      Official CVE record (current)
                    </a>
                  </article>
                );
              })
            )}
          </section>
        );
      })}
    </section>
  );
}

export function ReplayOrdering({ manifest }: { manifest: StoredRadarCheckpoint }) {
  let unscored = 0;
  let unknownEpss = 0;
  let unknownDate = 0;
  for (const item of Object.values(manifest.items)) {
    if (item.primaryVersion === null) unscored += 1;
    if (item.epss === null) unknownEpss += 1;
    if (item.publishedAt === null) unknownDate += 1;
  }
  return (
    <section
      className="ledger-section"
      aria-labelledby="replay-ordering-heading"
      data-testid="replay-ordering"
    >
      <h2 id="replay-ordering-heading">Ordering policy in this replay</h2>
      <div className="ledger-ordering">
        <strong>{`Ranking policy ${manifest.policyVersion}. Ties fall back to publication date, then CVE ID ASCII.`}</strong>
        <span className="ledger-meta">
          {`Unknown EPSS sorts after every known value, including zero. Coverage: ${manifest.cohortCount} retained PUBLISHED records in checkpoint ${manifest.checkpointDate}. ${unscored} unscored, ${unknownEpss} without EPSS, ${unknownDate} without a publication date. Join gaps are reported, never silently dropped.`}
        </span>
      </div>
    </section>
  );
}

export function ReplayUnavailable({ reason }: { reason: string }) {
  return (
    <section
      className="ledger-section"
      aria-labelledby="replay-unavailable-heading"
      data-testid="replay-unavailable"
    >
      <h2 id="replay-unavailable-heading">Snapshot unavailable</h2>
      <div className="ledger-notice" role="alert">
        <p data-testid="replay-unavailable-reason">{reason}</p>
        <p data-testid="replay-unavailable-guarantee">Current data is never substituted.</p>
      </div>
    </section>
  );
}

export function ReplayModelChanged({ reason }: { reason: string }) {
  return (
    <section
      className="ledger-section"
      aria-labelledby="replay-model-heading"
      data-testid="replay-model-changed"
    >
      <h2 id="replay-model-heading">Snapshot unavailable</h2>
      <div className="ledger-notice" role="alert">
        <p data-testid="replay-model-changed-reason">{reason}</p>
        <p>
          Forecasts use different models; change is not compared. Current data is never substituted.
        </p>
      </div>
    </section>
  );
}
