const NAV_ITEMS = [
  { label: "Overview", href: "/" },
  { label: "Search", href: "/explore" },
  { label: "Priority", href: "/priority" },
  { label: "Radar", href: "/radar" },
  { label: "Replay", href: "/replay" },
  { label: "Method", href: "/methodology" },
] as const;

type MastheadProps = {
  current?: (typeof NAV_ITEMS)[number]["label"];
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
          item.label === current ? (
            <span key={item.label} className="ledger-nav-link ledger-nav-link-current" aria-current="page">
              {item.label} (current)
            </span>
          ) : (
            <a key={item.label} className="ledger-nav-link" href={item.href}>
              {item.label}
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
