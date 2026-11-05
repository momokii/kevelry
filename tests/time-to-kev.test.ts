import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  bucketForLag,
  buildTimeToKev,
  cohortForYear,
  lagDays,
  LAG_BUCKETS,
} from "../src/lib/time-to-kev";

const STAMP = "2026-11-01T00:00:00.000Z";
const dirs: string[] = [];
const dbs: CveDatabase[] = [];

function makeDb(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-ttk-"));
  dirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  dbs.push(db);
  return db;
}

afterEach(() => {
  while (dbs.length > 0) {
    try {
      (dbs.pop() as CveDatabase).close();
    } catch {
      /* best effort */
    }
  }
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function seed(
  db: CveDatabase,
  id: string,
  published: string | null,
  added: string | null,
  state = "PUBLISHED",
): void {
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT OR REPLACE INTO cve_records (cve_id, data_version, state, date_published, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(id, "5.1", state, published, "d", STAMP, STAMP);
    if (added !== null) {
      db.handle
        .prepare(
          "INSERT OR REPLACE INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
        )
        .run(id, added, STAMP, STAMP);
    }
  });
}

describe("lag arithmetic", () => {
  it("measures whole days and rejects unparseable input", () => {
    expect(lagDays("2026-01-01", "2026-01-31")).toBe(30);
    expect(lagDays("2026-01-31", "2026-01-01")).toBe(-30);
    expect(lagDays("2026-01-01T10:00:00.000Z", "2026-01-02T09:00:00.000Z")).toBe(0);
    expect(lagDays("nope", "2026-01-01")).toBeNull();
  });

  it("buckets every boundary exactly once", () => {
    expect(bucketForLag(-5)).toBe("pre-publication");
    expect(bucketForLag(0)).toBe("pre-publication");
    expect(bucketForLag(1)).toBe("0-30d");
    expect(bucketForLag(30)).toBe("0-30d");
    expect(bucketForLag(31)).toBe("31-90d");
    expect(bucketForLag(90)).toBe("31-90d");
    expect(bucketForLag(91)).toBe("91-365d");
    expect(bucketForLag(365)).toBe("91-365d");
    expect(bucketForLag(366)).toBe("1-5y");
    expect(bucketForLag(1825)).toBe("1-5y");
    expect(bucketForLag(1826)).toBe("gt-5y");
  });

  it("collapses older cohorts into a labelled node", () => {
    expect(cohortForYear(2026, 2021)).toBe("2026");
    expect(cohortForYear(2021, 2021)).toBe("2021 or earlier");
    expect(cohortForYear(2005, 2021)).toBe("2021 or earlier");
  });
});

describe("time-to-KEV flow", () => {
  it("counts each record once, excludes unknown dates, and states them", () => {
    const db = makeDb();
    seed(db, "CVE-2099-0001", "2026-01-01", "2026-01-11"); // 10d -> 0-30d
    seed(db, "CVE-2099-0002", "2026-01-01", "2026-03-01"); // 59d -> 31-90d
    seed(db, "CVE-2099-0003", "2024-05-01", "2026-06-01"); // >1y -> 1-5y
    seed(db, "CVE-2099-0004", "2026-01-01", "2025-12-20"); // listed before -> pre
    seed(db, "CVE-2099-0005", null, "2026-01-01"); // excluded: no publication
    seed(db, "CVE-2099-0006", "2026-01-01", null); // not KEV-listed at all
    seed(db, "CVE-2099-0007", "2026-01-01", "2026-01-02", "REJECTED"); // excluded: not published

    const flow = buildTimeToKev(db, 2021);
    expect(flow.eligible).toBe(4);
    expect(flow.excluded).toBe(1);
    const total = flow.links.reduce((sum, link) => sum + link.count, 0);
    expect(total).toBe(4);
    const byLag = new Map(
      flow.nodes.filter((node) => node.column === "lag").map((node) => [node.label, node.total]),
    );
    expect(byLag.get("Within 30 days")).toBe(1);
    expect(byLag.get("31–90 days")).toBe(1);
    expect(byLag.get("1–5 years")).toBe(1);
    expect(byLag.get("Listed on/before publication")).toBe(1);
    // Every lag bucket present is one of the declared buckets, in order.
    const order = flow.nodes.filter((node) => node.column === "lag").map((node) => node.id);
    expect(order).toEqual(
      LAG_BUCKETS.filter((bucket) =>
        byLag.has(
          bucket === "pre-publication"
            ? "Listed on/before publication"
            : bucket === "0-30d"
              ? "Within 30 days"
              : bucket === "31-90d"
                ? "31–90 days"
                : bucket === "91-365d"
                  ? "91–365 days"
                  : bucket === "1-5y"
                    ? "1–5 years"
                    : "Over 5 years",
        ),
      ).map((bucket) => `lag:${bucket}`),
    );
  });

  it("reports median and within-30 share over confirmed-after-publication records", () => {
    const db = makeDb();
    seed(db, "CVE-2099-0001", "2026-01-01", "2026-01-11"); // 10
    seed(db, "CVE-2099-0002", "2026-01-01", "2026-01-21"); // 20
    seed(db, "CVE-2099-0003", "2026-01-01", "2026-04-11"); // 100
    seed(db, "CVE-2099-0004", "2026-01-01", "2025-12-01"); // negative, excluded from both

    const flow = buildTimeToKev(db, 2021);
    expect(flow.eligible).toBe(4);
    expect(flow.within30).toBe(2);
    expect(flow.within30Share).toBe("50.0%");
    expect(flow.medianDays).toBe(20);
    expect(flow.fastest.map((entry) => entry.days)).toEqual([10, 20, 100]);
  });

  it("returns an honest empty shape when nothing is eligible", () => {
    const db = makeDb();
    const flow = buildTimeToKev(db, 2021);
    expect(flow).toMatchObject({ eligible: 0, excluded: 0, medianDays: null, within30Share: "0%" });
    expect(flow.nodes).toEqual([]);
    expect(flow.links).toEqual([]);
  });
});
