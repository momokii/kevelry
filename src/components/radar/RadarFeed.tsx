"use client";

import { useEffect, useMemo, useState } from "react";

import { Masthead } from "@/components/ledger/Masthead";

import { KIND_META, type RadarUiDay, type RadarUiEvent, type RadarUiKind } from "./radar-fixtures";

const KIND_ORDER: RadarUiKind[] = [
  "kev-added",
  "kev-removed",
  "cna-changed",
  "forecast-changed",
  "corrected",
  "rejected",
  "list-entered",
  "list-exited",
  "rank-moved",
];

const FIELD_SYMBOLS: Record<string, string> = {
  unchanged: "[=]",
  added: "[+]",
  removed: "[-]",
  changed: "[~]",
  unknown: "[?]",
};

function rankText(rank: number | null): string {
  return rank === null ? "not listed" : `position ${String(rank + 1)}`;
}

function EventRow({
  event,
  selected,
  onSelect,
}: {
  event: RadarUiEvent;
  selected: boolean;
  onSelect: () => void;
}) {
  const meta = KIND_META[event.kind];
  return (
    <li className="ledger-row-item">
      <button
        type="button"
        className="ledger-row ledger-row-button"
        data-testid={`radar-event-${event.cveId}-${event.kind}`}
        aria-pressed={selected}
        aria-label={`${meta.label}: ${event.cveId}. ${event.detail}`}
        onClick={onSelect}
      >
        <span className="ledger-row-id">{event.cveId}</span>
        <span className="ledger-row-title" data-testid={`radar-kind-${event.eventId}`}>
          <span className="ledger-compare-change">
            {meta.symbol} {meta.label}
          </span>
        </span>
        <span className="ledger-row-signals ledger-row-block" data-testid={`radar-detail-${event.eventId}`}>
          {event.detail}
        </span>
        <span className="ledger-row-signals ledger-row-block">
          Observed {event.sourceRevision}; rank {rankText(event.beforeRank)} to{" "}
          {rankText(event.afterRank)}.
        </span>
      </button>
    </li>
  );
}

function Inspector({ event, day }: { event: RadarUiEvent | null; day: RadarUiDay }) {
  if (event === null) {
    return (
      <div className="ledger-compare" data-testid="radar-inspector-empty">
        <div className="ledger-compare-cell">
          <span className="ledger-compare-label">Inspector</span>
          <p>No change selected for this pair of snapshots.</p>
        </div>
      </div>
    );
  }
  const meta = KIND_META[event.kind];
  return (
    <div data-testid="radar-inspector">
      <h3 data-testid="radar-inspector-title">
        {meta.symbol} {meta.label}: {event.cveId}
      </h3>
      <p className="ledger-row-signals" data-testid="radar-inspector-detail">
        {event.detail}
      </p>
      {event.kind === "rank-moved" ? (
        <p className="ledger-row-signals" data-testid="radar-inspector-rank-note">
          [R] Rank-only move: source signals are unchanged. This reorder is not a source change.
        </p>
      ) : null}
      <div className="ledger-compare" data-testid="radar-inspector-fields">
        {event.fields.map((row) => (
          <div className="ledger-compare" key={`${event.eventId}-${row.field}`}>
            <div
              className="ledger-compare-cell"
              data-testid={`radar-before-${event.eventId}-${row.field}`}
            >
              <span className="ledger-compare-label">Before: {day.beforeDate} snapshot</span>
              <p>
                {row.field}: {row.before ?? "unknown"}
              </p>
            </div>
            <div
              className="ledger-compare-cell"
              data-testid={`radar-after-${event.eventId}-${row.field}`}
            >
              <span className="ledger-compare-label">After: {day.afterDate} snapshot</span>
              <p>
                {row.field}: {row.after ?? "unknown"}
              </p>
            </div>
            <p className="ledger-compare-change">
              {FIELD_SYMBOLS[row.change]} {row.field}:{" "}
              {row.change === "unchanged"
                ? "identical in both snapshots"
                : row.change === "added"
                  ? "appeared in the new snapshot"
                  : row.change === "removed"
                    ? "absent from the new snapshot"
                    : row.change === "unknown"
                      ? "missing value is unknown, not zero and not interpolated"
                      : "observed value moved between snapshots"}
            </p>
          </div>
        ))}
      </div>
      <div className="ledger-evidence" data-testid="radar-inspector-evidence">
        <span className="ledger-evidence-symbol" aria-hidden="true">
          =
        </span>
        <span className="ledger-evidence-state">Retained snapshots</span>
        <span data-testid="radar-inspector-evidence-detail">
          Before {day.beforeDate} observed {day.beforeObservedAt} ({day.beforeRevisionLabel}); after{" "}
          {day.afterDate} observed {day.afterObservedAt} ({day.afterRevisionLabel}); source revision{" "}
          {event.sourceRevision}. Forecast values are observed only; the model does not explain why
          they moved. KEV listing records catalog membership only; it does not record when exploitation began.
        </span>
      </div>
    </div>
  );
}

export function RadarFeed({ days }: { days: RadarUiDay[] }) {
  const [dayIndex, setDayIndex] = useState(() => (days.length > 0 ? days.length - 2 : 0));
  const [kindFilter, setKindFilter] = useState<RadarUiKind | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
  }, []);

  const day: RadarUiDay | undefined = days[dayIndex];
  const visibleEvents = useMemo(() => {
    if (day === undefined) return [];
    if (kindFilter === null) return day.events;
    return day.events.filter((event) => event.kind === kindFilter);
  }, [day, kindFilter]);

  const selected: RadarUiEvent | null = useMemo(() => {
    if (day === undefined) return null;
    if (selectedId !== null) {
      const found = day.events.find((event) => event.eventId === selectedId);
      if (found !== undefined) return found;
    }
    return day.events[0] ?? null;
  }, [day, selectedId]);

  // If filtering unmounted the focused event button, focus falls back to
  // <body>; recover to the feed heading so keyboard users keep a visible target.
  useEffect(() => {
    if (typeof document === "undefined") return;
    if (document.activeElement === document.body) {
      document.getElementById("radar-feed-heading")?.focus({ preventScroll: true });
    }
  }, [kindFilter, dayIndex]);

  if (day === undefined || days.length === 0) {
    return (
      <main
        className="ledger-page"
        data-testid="radar-root"
        id="main-content"
        data-hydrated={hydrated ? "true" : "false"}
      >
        <Masthead current="Radar" testId="radar-masthead" />
        <h1>Change Radar</h1>
        <p data-testid="radar-unavailable">
          Snapshot unavailable: no retained checkpoints to compare.
        </p>
      </main>
    );
  }

  const kindsPresent = KIND_ORDER.filter((kind) => day.events.some((event) => event.kind === kind));

  return (
    <main
      className="ledger-page"
      data-testid="radar-root"
      id="main-content"
      data-hydrated={hydrated ? "true" : "false"}
    >
      <Masthead current="Radar" testId="radar-masthead" />
      <h1>Change Radar</h1>
      <p className="ledger-meta" data-testid="radar-lede">
        What changed between two retained daily snapshots, with the before and after values behind
        every entry. Rank-only movement is labeled as such and never presented as a source change.
      </p>

      <section className="ledger-section" aria-labelledby="radar-day-heading">
        <h2 id="radar-day-heading">Snapshot pair</h2>
        <div className="ledger-snapshot">
          <label className="ledger-meta" htmlFor="radar-day-select">
            Retained checkpoints under comparison
          </label>
          <select
            id="radar-day-select"
            className="ledger-snapshot-select"
            data-testid="radar-day-select"
            value={String(dayIndex)}
            onChange={(entry) => {
              setDayIndex(Number(entry.target.value));
              setSelectedId(null);
              setKindFilter(null);
            }}
          >
            {days.map((option, index) => (
              <option key={`${option.beforeDate}-${option.afterDate}`} value={String(index)}>
                {option.afterDate} vs {option.beforeDate}
                {option.events.length === 0 ? " (quiet day)" : ""}
              </option>
            ))}
          </select>
          <p className="ledger-snapshot-note" data-testid="radar-day-note">
            Before {day.beforeDate} observed {day.beforeObservedAt}; after {day.afterDate} observed{" "}
            {day.afterObservedAt}. Policy v1
            {day.policyChanged ? " changed between snapshots" : " unchanged"}; cohort{" "}
            {day.cohortBefore} to {day.cohortAfter} retained PUBLISHED records
            {day.cohortChanged ? " (cohort changed)" : ""}.
          </p>
        </div>
      </section>

      {day.events.length === 0 ? (
        <section
          className="ledger-section"
          aria-labelledby="radar-quiet-heading"
          data-testid="radar-quiet"
        >
          <h2 id="radar-quiet-heading">Quiet day</h2>
          <p data-testid="radar-quiet-copy">
            [~] Quiet day: no source changes observed between {day.beforeDate} and {day.afterDate}.
            The retained snapshots match, so the feed stays empty rather than inventing activity.
          </p>
          <div className="ledger-evidence" data-testid="radar-quiet-evidence">
            <span className="ledger-evidence-symbol" aria-hidden="true">
              =
            </span>
            <span className="ledger-evidence-state">Retained snapshots</span>
            <span>
              Before {day.beforeDate} observed {day.beforeObservedAt} ({day.beforeRevisionLabel});
              after {day.afterDate} observed {day.afterObservedAt} ({day.afterRevisionLabel}).
            </span>
          </div>
        </section>
      ) : (
        <>
          <section className="ledger-section" aria-labelledby="radar-filter-heading">
            <h2 id="radar-filter-heading">Filter by change kind</h2>
            <div className="ledger-filter-group" role="group" aria-label="Change kind filter">
              <button
                type="button"
                className="ledger-filter-chip"
                data-testid="radar-filter-all"
                aria-pressed={kindFilter === null}
                onClick={() => setKindFilter(null)}
              >
                {kindFilter === null ? "[x] All kinds" : "[ ] All kinds"}
              </button>
              {kindsPresent.map((kind) => (
                <button
                  type="button"
                  key={kind}
                  className="ledger-filter-chip"
                  data-testid={`radar-filter-${kind}`}
                  aria-pressed={kindFilter === kind}
                  onClick={() => setKindFilter(kindFilter === kind ? null : kind)}
                >
                  {kindFilter === kind ? "[x]" : "[ ]"} {KIND_META[kind].symbol}{" "}
                  {KIND_META[kind].label}
                </button>
              ))}
            </div>
          </section>

          <section className="ledger-section" aria-labelledby="radar-feed-heading">
            <h2 id="radar-feed-heading" tabIndex={-1}>
              Change feed: {day.afterDate} vs {day.beforeDate} ({String(visibleEvents.length)}{" "}
              {visibleEvents.length === 1 ? "entry" : "entries"})
            </h2>
            <p className="ledger-meta" role="status" data-testid="radar-filter-status">
              Showing {visibleEvents.length} of {day.events.length} entries
              {kindFilter === null ? "" : ` for ${KIND_META[kindFilter].label}`}.
            </p>
            <div data-testid="radar-feed">
              {visibleEvents.length === 0 ? (
                <p data-testid="radar-filter-empty">
                  No entries of this kind in this snapshot pair. Clear the filter to see the full
                  feed.
                </p>
              ) : (
                <ul className="ledger-feed-list">
                  {visibleEvents.map((event) => (
                    <EventRow
                      key={event.eventId}
                      event={event}
                      selected={selected?.eventId === event.eventId}
                      onSelect={() => setSelectedId(event.eventId)}
                    />
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section className="ledger-section" aria-labelledby="radar-inspector-heading">
            <h2 id="radar-inspector-heading">Evidence inspector</h2>
            <Inspector event={selected} day={day} />
          </section>
        </>
      )}
    </main>
  );
}
