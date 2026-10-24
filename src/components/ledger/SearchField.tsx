export type SearchState = "default" | "populated" | "pending" | "invalid" | "empty" | "error";

type SearchFieldProps = {
  state: SearchState;
  query?: string;
  testId: string;
};

const STATUS_COPY: Record<SearchState, string> = {
  default: "Type a CVE identifier or description words, then run search.",
  populated: "Query ready: CVE-2026-1234 buffer overflow.",
  pending: "Searching local snapshots. Results will be announced once.",
  invalid: "Invalid query: use at least 3 characters; wildcard-only queries are rejected.",
  empty: "No matches in the retained snapshot. Try fewer filters.",
  error: "Search failed against the local index. Last-known-good data is intact; retry below.",
};

export function SearchField({ state, query = "", testId }: SearchFieldProps) {
  const value = state === "populated" || state === "pending" ? query || "CVE-2026-1234 buffer overflow" : query;
  const isPending = state === "pending";
  return (
    <div data-testid={testId}>
      <div className="ledger-search">
        <input
          className="ledger-search-input"
          type="search"
          defaultValue={value}
          placeholder="Search CVE identifier or description"
          aria-label="Search CVE records"
          aria-invalid={state === "invalid"}
          aria-busy={isPending}
          disabled={isPending}
          data-testid={`${testId}-input`}
        />
        <button
          className="ledger-search-button"
          type="button"
          disabled={isPending}
          aria-disabled={isPending}
          data-testid={`${testId}-action`}
        >
          {isPending ? "Searching" : "Search"}
        </button>
      </div>
      {state === "invalid" || state === "error" ? (
        <p className="ledger-search-error" role="alert" data-testid={`${testId}-feedback`}>
          {STATUS_COPY[state]}
        </p>
      ) : (
        <p className="ledger-search-status" role={isPending ? "status" : undefined} data-testid={`${testId}-feedback`}>
          {STATUS_COPY[state]}
        </p>
      )}
    </div>
  );
}
