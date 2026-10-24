const FILTERS = ["Known exploited", "Highest forecast", "New critical", "Rising forecast"] as const;

type FilterGroupProps = {
  selected?: string[];
  disabled?: boolean;
  wrapped?: boolean;
  testId: string;
};

export function FilterGroup({ selected = [], disabled = false, wrapped = false, testId }: FilterGroupProps) {
  const items = wrapped
    ? [...FILTERS, "Vendor label with a forty-character demonstration string", "Unscored records included"]
    : [...FILTERS];
  return (
    <div data-testid={testId}>
      <div className="ledger-filter-group" role="group" aria-label="Priority view filters">
        {items.map((item) => (
          <button
            key={item}
            className="ledger-filter-chip"
            type="button"
            aria-pressed={selected.includes(item)}
            disabled={disabled}
            data-testid={`${testId}-chip`}
          >
            {selected.includes(item) ? "[x] " : "[ ] "}
            {item}
          </button>
        ))}
      </div>
      <p className="ledger-meta" data-testid={`${testId}-reset`}>
        {selected.length > 0 ? `${selected.length} selected. Clear resets to the full cohort.` : "No filters selected."}
      </p>
    </div>
  );
}
