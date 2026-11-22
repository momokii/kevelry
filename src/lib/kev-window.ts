// Bounded KEV catalog reads for one day window.
//
// The KEV catalog is a small, published list (one row per listed CVE), so a
// window read is a bounded scan over `kev_entries`, not a corpus query. It
// exists as a loader rather than SQL in a caller because the AI tool layer is
// not allowed to hold SQL: tools validate arguments, loaders read.
//
// Contract:
// - read-only and parameterized; the window is validated to `YYYY-MM-DD` shape
//   by the caller and compared as a day prefix, because `date_added` is a
//   day-precision catalog fact stored as an ISO timestamp.
// - `due_date` is the catalog's own published date, never inferred; a missing or
//   malformed due date is ineligible for either due count.
// - rows are additions only; `totalAdditions` counts the window, `items` is the
//   newest-first page.

import type { CveDatabase } from "./db";
import { kevRansomwareUseOf, type KevRansomwareUse } from "./record-display";

export interface KevWindowQuery {
  /** Inclusive first day, `YYYY-MM-DD`. */
  startDay: string;
  /** Inclusive last day, `YYYY-MM-DD`. */
  endDay: string;
  /** Row cap for `items`; the counts are never truncated. */
  limit: number;
}

export interface KevWindowItem {
  cveId: string;
  dateAdded: string;
  dueDate: string | null;
  ransomwareUse: KevRansomwareUse;
}

export interface KevWindowResult {
  totalAdditions: number;
  /** Additions whose catalog due date falls inside the same window. */
  dueInWindow: number;
  /** Additions whose due date is still open today or later. */
  dueFromNow: number;
  items: KevWindowItem[];
}

/** Additions inside `[startDay, endDay]`, newest first, plus the two due counts. */
export function readKevWindow(db: CveDatabase, query: KevWindowQuery): KevWindowResult {
  const counts = db.handle
    .prepare(
      "SELECT " +
        "SUM(CASE WHEN substr(date_added, 1, 10) >= ? AND substr(date_added, 1, 10) <= ? THEN 1 ELSE 0 END) AS additions, " +
        "SUM(CASE WHEN substr(date_added, 1, 10) >= ? AND substr(date_added, 1, 10) <= ? " +
        "AND due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' " +
        "AND due_date >= ? AND due_date <= ? THEN 1 ELSE 0 END) AS due_in_window, " +
        "SUM(CASE WHEN substr(date_added, 1, 10) >= ? AND substr(date_added, 1, 10) <= ? " +
        "AND due_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' " +
        "AND due_date >= ? THEN 1 ELSE 0 END) AS due_from_now " +
        "FROM kev_entries",
    )
    .get(
      query.startDay,
      query.endDay,
      query.startDay,
      query.endDay,
      query.startDay,
      query.endDay,
      query.startDay,
      query.endDay,
      query.endDay,
    ) as { additions: number | null; due_in_window: number | null; due_from_now: number | null };

  const rows = db.handle
    .prepare(
      "SELECT cve_id, date_added, due_date, ransomware_known FROM kev_entries " +
        "WHERE substr(date_added, 1, 10) >= ? AND substr(date_added, 1, 10) <= ? " +
        "ORDER BY substr(date_added, 1, 10) DESC, cve_id ASC LIMIT ?",
    )
    .all(query.startDay, query.endDay, query.limit) as Array<{
    cve_id: string;
    date_added: string;
    due_date: string | null;
    ransomware_known: number | null;
  }>;

  return {
    totalAdditions: counts.additions ?? 0,
    dueInWindow: counts.due_in_window ?? 0,
    dueFromNow: counts.due_from_now ?? 0,
    items: rows.map((row) => ({
      cveId: row.cve_id,
      dateAdded: row.date_added,
      dueDate: row.due_date,
      ransomwareUse: kevRansomwareUseOf(row.ransomware_known),
    })),
  };
}
