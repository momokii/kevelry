// The empty desk's three questions.
//
// A suggestion is a question this instance can actually answer, paired with the
// count that made it offerable. Both facts are read from the accepted corpus on
// the request that renders the page, and a candidate whose count is zero is
// dropped rather than rendered with a hopeful "0" — an invitation to a question
// the data cannot answer is the one dishonest thing an empty state can do.
//
// Ordering is fixed, so a suggestion's position is a property of the corpus and
// not of a shuffle: KEV additions, KEV deadlines, exploit-tagged records, the
// corpus itself, then the EPSS-scored cohort. At most three render; a tiny
// corpus may therefore offer fewer, and that is the honest result. The
// corpus-shape question ranks above the EPSS cohort because it is answerable
// whenever any record is published, while the cohort question needs scores.

import { readCoverageTotals } from "../aggregates";
import type { CveDatabase } from "../db";
import { countKevDueBetween, readKevWindow } from "../kev-window";

/** How far the suggestions look. One constant, so copy and count agree. */
export const SUGGESTION_WINDOW_DAYS = 30;

/** Exactly three: the empty state is an invitation, not a menu. */
export const SUGGESTION_LIMIT = 3;

export interface AssistantSuggestion {
  /** Stable id for the button and its test. */
  id: string;
  /** The question the button submits, verbatim. */
  question: string;
  /** The size of the set the question asks about. */
  count: number;
  /** What the count counts, printed beside it (never a bare number). */
  countLabel: string;
}

export interface SuggestionCounts {
  /** Current PUBLISHED records: the corpus the desk answers about. */
  published: number;
  /** KEV additions inside the window. */
  kevAdditions: number;
  /** KEV catalog due dates inside the next window. */
  kevDueSoon: number;
  /** Records carrying a publisher-tagged exploit reference. */
  exploitTagged: number;
  /** Records with an accepted EPSS forecast on the current score date. */
  epssScored: number;
}

export interface SuggestionCandidate extends AssistantSuggestion {
  available: boolean;
}

function dayOffset(day: string, offset: number): string {
  const ms = Date.parse(`${day}T00:00:00.000Z`);
  return new Date(ms + offset * 86_400_000).toISOString().slice(0, 10);
}

/**
 * Builds every candidate with its count, keeping the unavailable ones so a test
 * can assert the gate rather than infer it from an absence.
 */
export function buildSuggestionCandidates(counts: SuggestionCounts): SuggestionCandidate[] {
  return [
    {
      id: "kev-additions",
      question: `Which KEV entries were added in the last ${String(SUGGESTION_WINDOW_DAYS)} days?`,
      count: counts.kevAdditions,
      countLabel: "KEV additions",
      available: counts.kevAdditions > 0,
    },
    {
      id: "kev-due",
      question: `Which KEV entries are due in the next ${String(SUGGESTION_WINDOW_DAYS)} days?`,
      count: counts.kevDueSoon,
      countLabel: "catalog due dates",
      available: counts.kevDueSoon > 0,
    },
    {
      id: "exploit-tagged",
      question: "Which records carry a publisher exploit tag?",
      count: counts.exploitTagged,
      countLabel: "tagged records",
      available: counts.exploitTagged > 0,
    },
    {
      id: "corpus-size",
      question: "How large is this corpus, and how much of it is KEV-listed?",
      count: counts.published,
      countLabel: "published records",
      available: counts.published > 0,
    },
    {
      id: "epss-cohort",
      question: "Which records carry the highest EPSS forecast right now?",
      count: counts.epssScored,
      countLabel: "scored records",
      available: counts.epssScored > 0,
    },
  ];
}

/** The candidates that may render, in their fixed order, capped at three. */
export function buildAssistantSuggestions(counts: SuggestionCounts): AssistantSuggestion[] {
  return buildSuggestionCandidates(counts)
    .filter((candidate) => candidate.available)
    .slice(0, SUGGESTION_LIMIT)
    .map(({ available: _available, ...suggestion }) => suggestion);
}

/** Reads the counts behind the suggestions from the accepted corpus. */
export function readSuggestionCounts(db: CveDatabase, now: Date = new Date()): SuggestionCounts {
  const today = now.toISOString().slice(0, 10);
  const additions = readKevWindow(db, {
    startDay: dayOffset(today, -(SUGGESTION_WINDOW_DAYS - 1)),
    endDay: today,
    // The counts are never truncated, and the empty state renders no rows.
    limit: 1,
  });
  const coverage = readCoverageTotals(db);
  return {
    published: coverage.published,
    kevAdditions: additions.totalAdditions,
    kevDueSoon: countKevDueBetween(db, {
      startDay: today,
      endDay: dayOffset(today, SUGGESTION_WINDOW_DAYS),
    }),
    exploitTagged: coverage.exploitTagged,
    epssScored: coverage.epssScored,
  };
}
