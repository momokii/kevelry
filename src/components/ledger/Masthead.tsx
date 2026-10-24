const NAV_ITEMS = ["Overview", "Search", "Priority", "Radar", "Method"] as const;

type MastheadProps = {
  current?: (typeof NAV_ITEMS)[number];
  historical?: boolean;
  menuOpen?: boolean;
  testId: string;
};

export function Masthead({ current = "Overview", historical = false, menuOpen = false, testId }: MastheadProps) {
  return (
    <header className="ledger-masthead" data-testid={testId}>
      <span className="ledger-brand">Evidence Ledger</span>
      <nav className="ledger-nav" aria-label="Primary">
        {NAV_ITEMS.map((item) =>
          item === current ? (
            <span key={item} className="ledger-nav-link ledger-nav-link-current" aria-current="page">
              {item} (current)
            </span>
          ) : (
            <a key={item} className="ledger-nav-link" href="#section-masthead">
              {item}
            </a>
          ),
        )}
      </nav>
      <span className="ledger-meta" data-testid={`${testId}-menu`}>
        {menuOpen ? "Menu open: all destinations listed vertically" : "Menu collapsed: destinations wrap inline"}
      </span>
      {historical ? (
        <p className="ledger-historical-banner" data-testid={`${testId}-banner`}>
          Historical context: retained snapshot dated 2026-10-24. Current links are labeled current.
        </p>
      ) : null}
    </header>
  );
}
