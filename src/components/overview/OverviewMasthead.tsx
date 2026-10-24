const NAV_ITEMS = [
  { label: "Overview", href: "/" },
  { label: "Search", href: "/explore" },
  { label: "Priority", href: "/priority" },
  { label: "Radar", href: "/radar" },
  { label: "Replay", href: "/replay" },
  { label: "Method", href: "/method" },
] as const;

export function OverviewMasthead() {
  return (
    <header className="ledger-masthead" data-testid="overview-masthead">
      <span className="ledger-brand">Evidence Ledger</span>
      <nav className="ledger-nav" aria-label="Primary">
        {NAV_ITEMS.map((item) =>
          item.label === "Overview" ? (
            <span
              key={item.label}
              className="ledger-nav-link ledger-nav-link-current"
              aria-current="page"
            >
              {item.label} (current)
            </span>
          ) : (
            <a key={item.label} className="ledger-nav-link" href={item.href}>
              {item.label}
            </a>
          ),
        )}
      </nav>
    </header>
  );
}
