"use client";

import { useDisplayPrefs, WATCH_MAX_IDS } from "./DisplayPrefs";

/**
 * Browser-private watch toggle for one CVE ID. No account, no server record:
 * the list lives in localStorage only, so anonymity holds by construction.
 * Malformed IDs never toggle; the 200-ID cap refuses silently in state and
 * says so in the title.
 */
export function WatchStar({ cveId, testId }: { cveId: string; testId?: string }) {
  const { watchedIds, toggleWatch } = useDisplayPrefs();
  const watched = watchedIds.includes(cveId);
  const atCap = !watched && watchedIds.length >= WATCH_MAX_IDS;

  return (
    <button
      type="button"
      className={`watch-star${watched ? " is-watched" : ""}`}
      aria-pressed={watched}
      aria-label={watched ? `Stop watching ${cveId}` : `Watch ${cveId}`}
      title={
        atCap
          ? `Watch list is full (${WATCH_MAX_IDS} records). Unwatch one first.`
          : watched
            ? `Stop watching ${cveId}`
            : `Watch ${cveId}`
      }
      disabled={atCap}
      data-testid={testId ?? `watch-star-${cveId}`}
      onClick={() => toggleWatch(cveId)}
    >
      <svg
        width="18"
        height="18"
        viewBox="0 0 24 24"
        fill={watched ? "currentColor" : "none"}
        stroke="currentColor"
        strokeWidth={1.7}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M12 3.5l2.6 5.3 5.9.9-4.2 4.1 1 5.8-5.3-2.8-5.3 2.8 1-5.8L3.5 9.7l5.9-.9L12 3.5z" />
      </svg>
    </button>
  );
}
