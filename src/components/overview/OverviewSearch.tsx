export function OverviewSearch() {
  return (
    <div data-testid="overview-search">
      <form className="ledger-search" action="/explore" method="get" role="search">
        <input
          className="ledger-search-input"
          type="search"
          name="q"
          placeholder="Search CVE identifier or description"
          aria-label="Search CVE records"
          data-testid="overview-search-input"
        />
        <button className="ledger-search-button" type="submit" data-testid="overview-search-action">
          Search
        </button>
      </form>
      <p className="ledger-search-status" data-testid="overview-search-hint">
        Searches the retained local snapshot. Results show excerpts with official CVE record links.
      </p>
    </div>
  );
}
