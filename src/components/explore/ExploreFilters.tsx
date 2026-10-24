import {
  EXPLORE_LIMIT_OPTIONS,
  ExploreInitial,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
} from "./filter-meta";

type ExploreFiltersProps = {
  initial: ExploreInitial;
};

/**
 * Native GET filter form: no client script, every control keyboard-operable
 * by construction. Submits to /explore; the server re-renders with the typed
 * values kept, including after an invalid-filter error.
 */
export function ExploreFilters({ initial }: ExploreFiltersProps) {
  return (
    <form
      method="get"
      action="/explore"
      aria-label="CVE search filters"
      data-testid="explore-filters"
      className="ledger-explore-form"
    >
      <div className="ledger-search">
        <input
          className="ledger-search-input"
          type="search"
          name="q"
          defaultValue={initial.q}
          placeholder="Search CVE identifier or description"
          aria-label="Search CVE records"
          maxLength={200}
          data-testid="explore-query"
        />
        <button className="ledger-search-button" type="submit" data-testid="explore-submit">
          Search
        </button>
      </div>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Published date range, UTC, start inclusive, end exclusive
        </legend>
        <div className="ledger-explore-dates">
          <label className="ledger-explore-label" htmlFor="explore-date-start">
            Published on or after
            <input
              id="explore-date-start"
              className="ledger-explore-date"
              type="date"
              name="dateStart"
              defaultValue={initial.dateStart}
              data-testid="explore-date-start"
            />
          </label>
          <label className="ledger-explore-label" htmlFor="explore-date-end">
            Published before
            <input
              id="explore-date-end"
              className="ledger-explore-date"
              type="date"
              name="dateEnd"
              defaultValue={initial.dateEnd}
              data-testid="explore-date-end"
            />
          </label>
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Severity bands, primary CNA metric with version labels
        </legend>
        <div className="ledger-filter-group" role="group" aria-label="Severity bands">
          {SEVERITY_ORDER.map((band) => (
            <label key={band} className="ledger-filter-chip ledger-explore-chip">
              <input
                type="checkbox"
                name="severity"
                value={band}
                defaultChecked={initial.severity.includes(band)}
                data-testid={`explore-severity-${band}`}
              />
              <span>{SEVERITY_LABELS[band]}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">Known-exploited membership</legend>
        <div
          className="ledger-filter-group"
          role="radiogroup"
          aria-label="Known-exploited membership"
        >
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="all"
              defaultChecked={initial.kev === "all"}
              data-testid="explore-kev-all"
            />
            <span>Any KEV status</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="only"
              defaultChecked={initial.kev === "only"}
              data-testid="explore-kev-only"
            />
            <span>KEV-listed only</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="excluded"
              defaultChecked={initial.kev === "excluded"}
              data-testid="explore-kev-excluded"
            />
            <span>Not KEV-listed</span>
          </label>
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">Forecast presence, same snapshot, same model</legend>
        <div className="ledger-filter-group" role="radiogroup" aria-label="Forecast presence">
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="all"
              defaultChecked={initial.epss === "all"}
              data-testid="explore-epss-all"
            />
            <span>Any forecast status</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="present"
              defaultChecked={initial.epss === "present"}
              data-testid="explore-epss-present"
            />
            <span>Forecast present</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="absent"
              defaultChecked={initial.epss === "absent"}
              data-testid="explore-epss-absent"
            />
            <span>Forecast unavailable</span>
          </label>
        </div>
      </fieldset>

      <div className="ledger-explore-actions">
        <label className="ledger-explore-label" htmlFor="explore-limit">
          Results per page
          <select
            id="explore-limit"
            name="limit"
            defaultValue={String(initial.limit)}
            data-testid="explore-limit"
            className="ledger-snapshot-select"
          >
            {EXPLORE_LIMIT_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option} per page
              </option>
            ))}
          </select>
        </label>
        <button className="ledger-search-button" type="submit" data-testid="explore-apply">
          Apply filters
        </button>
        <a className="ledger-explore-clear" href="/explore" data-testid="explore-clear">
          Clear filters
        </a>
      </div>
    </form>
  );
}
