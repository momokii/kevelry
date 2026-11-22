// The empty desk's three questions.
//
// A suggestion is an invitation to a question the corpus can answer, so the gate
// is the count: a candidate whose count is zero is dropped, and a corpus with
// nothing to suggest offers nothing rather than three hopeful placeholders. The
// order is fixed so a suggestion's position is a property of the data.
//
// The second half reads a real (temporary) database through the same loader the
// page uses, so the counts are proven to come from the corpus and not from the
// shape of the builder.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import {
  SUGGESTION_LIMIT,
  buildAssistantSuggestions,
  buildSuggestionCandidates,
  readSuggestionCounts,
} from "../src/lib/ai/suggestions";
import { openDatabase, type CveDatabase } from "../src/lib/db";

const ZERO_COUNTS = {
  published: 0,
  kevAdditions: 0,
  kevDueSoon: 0,
  exploitTagged: 0,
  epssScored: 0,
};

const tempDirs: string[] = [];

function tempDatabase(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ai-suggestions-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

function dayOffset(days: number): string {
  return new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);
}

function seedKev(db: CveDatabase, cveId: string, addedDay: string, dueDay: string | null): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
          "title, description, description_lang, source_revision, created_at, updated_at) " +
          "VALUES (?, '5.1', 'PUBLISHED', ?, ?, ?, ?, 'en', 'rev-suggestions', ?, ?)",
      )
      .run(
        cveId,
        addedDay,
        addedDay,
        `Suggestion fixture ${cveId}`,
        `A fixture record for ${cveId}.`,
        addedDay,
        addedDay,
      );
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, due_date, vendor_project, product, recorded_at) " +
          "VALUES (?, ?, ?, ?, 'FixtureVendor', 'FixtureProduct', ?)",
      )
      .run(cveId, addedDay, addedDay, dueDay, addedDay);
  });
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

describe("suggestion candidates: availability follows the count", () => {
  it("offers nothing when every count is zero", () => {
    expect(buildAssistantSuggestions(ZERO_COUNTS)).toEqual([]);
  });

  it("drops a candidate whose count is zero and keeps the rest in fixed order", () => {
    const suggestions = buildAssistantSuggestions({
      published: 0,
      kevAdditions: 41,
      kevDueSoon: 0,
      exploitTagged: 12,
      epssScored: 900,
    });
    expect(suggestions.map((suggestion) => suggestion.id)).toEqual([
      "kev-additions",
      "exploit-tagged",
      "epss-cohort",
    ]);
    expect(suggestions.every((suggestion) => suggestion.count > 0)).toBe(true);
  });

  it("keeps the wording and the count together, never a bare number", () => {
    const [first] = buildAssistantSuggestions({
      ...ZERO_COUNTS,
      kevAdditions: 4,
    });
    expect(first?.question).toBe("Which KEV entries were added in the last 30 days?");
    expect(first?.count).toBe(4);
    expect(first?.countLabel).toBe("KEV additions");
  });

  it("never offers more than three, even when every candidate is available", () => {
    const all = {
      published: 1,
      kevAdditions: 1,
      kevDueSoon: 1,
      exploitTagged: 1,
      epssScored: 1,
    };
    expect(buildAssistantSuggestions(all)).toHaveLength(SUGGESTION_LIMIT);
    expect(buildSuggestionCandidates(all).filter((candidate) => candidate.available)).toHaveLength(
      5,
    );
  });
});

describe("suggestion counts: read from the corpus", () => {
  it("reads zeros from a corpus with no records, so the desk offers nothing", () => {
    const db = tempDatabase();
    const counts = readSuggestionCounts(db);
    expect(counts).toEqual({
      published: 0,
      kevAdditions: 0,
      kevDueSoon: 0,
      exploitTagged: 0,
      epssScored: 0,
    });
    expect(buildAssistantSuggestions(counts)).toEqual([]);
    db.close();
  });

  it("counts the KEV additions and the deadlines the window actually covers", () => {
    const db = tempDatabase();
    // Inside the 30-day additions window and inside the next 30 days of dues.
    seedKev(db, "CVE-2099-0101", dayOffset(-2), dayOffset(8));
    // Inside the additions window, but its due date is already past.
    seedKev(db, "CVE-2099-0102", dayOffset(-5), dayOffset(-1));
    // Outside both windows.
    seedKev(db, "CVE-2099-0103", dayOffset(-90), dayOffset(90));

    const counts = readSuggestionCounts(db);
    expect(counts.published).toBe(3);
    expect(counts.kevAdditions).toBe(2);
    expect(counts.kevDueSoon).toBe(1);
    const ids = buildAssistantSuggestions(counts).map((suggestion) => suggestion.id);
    expect(ids).toEqual(["kev-additions", "kev-due", "corpus-size"]);
    db.close();
  });
});
