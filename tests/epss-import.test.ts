// New-test justification (plan todo 10): the first EPSS daily CSV importer
// must prove full-file parsing (comment metadata, required columns, ID
// uniqueness, finite [0,1] numerics), exact-decimal storage with score date
// and model version, dated history retention, unknown-instead-of-zero
// lookups, and fail-closed aborts that leave the accepted snapshot alone.
// Fixtures use invented CVE-2099 IDs; the live URL test stays skipped unless
// EPSS_LIVE_TEST=1 explicitly opts in, so the suite never needs the network.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { type CveDatabase, openDatabase } from "../src/lib/db";
import {
  checkRisingEligible,
  computeDeltaPpText,
  EpssImportError,
  getAcceptedEpssDate,
  getEpssHistory,
  importEpssCsv,
  lookupEpss,
  parseEpssCsv,
} from "../src/lib/epss-import";

const tempDirs: string[] = [];

function makeDatabase(): CveDatabase {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-epss-test-"));
  tempDirs.push(dir);
  return openDatabase({ dataDir: dir });
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

const MODEL = "v2026.06.15";
const DAY_ONE = "2026-10-22";
const DAY_TWO = "2026-10-23";
const DAY_SEVEN_BACK = "2026-10-16";

function csvFor(scoreDate: string, model: string, lines: string[]): string {
  return [
    `#model_version:${model},score_date:${scoreDate}T12:00:28Z`,
    "cve,epss,percentile",
    ...lines,
  ].join("\n");
}

const DAY_ONE_CSV = csvFor(DAY_ONE, MODEL, [
  "CVE-2099-0001,0.10,0.80000",
  "CVE-2099-0002,0,0.05000",
  "CVE-2099-0003,0.1162,0.96047",
]);

const DAY_TWO_CSV = csvFor(DAY_TWO, MODEL, [
  "CVE-2099-0001,0.18,0.85000",
  "CVE-2099-0003,0.1162,0.96047",
]);

function epssDailyCount(db: CveDatabase): number {
  return (db.handle.prepare("SELECT COUNT(*) AS n FROM epss_daily").get() as { n: number }).n;
}

describe("EPSS daily CSV parsing", () => {
  it("reads comment metadata and requires the exact header", () => {
    const document = parseEpssCsv(DAY_ONE_CSV);
    expect(document.modelVersion).toBe(MODEL);
    expect(document.scoreDate).toBe(DAY_ONE);
    expect(document.rows).toHaveLength(3);
    expect(document.rows[0]).toEqual({
      cveId: "CVE-2099-0001",
      epssText: "0.10",
      percentileText: "0.80000",
    });
  });

  it("rejects every malformed shape with EpssImportError", () => {
    const cases: Array<[string, string]> = [
      ["empty input", ""],
      ["missing metadata comment", "cve,epss,percentile\nCVE-2099-0001,0.1,0.8"],
      [
        "missing model_version",
        `#score_date:${DAY_ONE}T12:00:28Z\ncve,epss,percentile\nCVE-2099-0001,0.1,0.8`,
      ],
      ["missing score_date", `#model_version:${MODEL}\ncve,epss,percentile\nCVE-2099-0001,0.1,0.8`],
      ["wrong header", csvFor(DAY_ONE, MODEL, []).replace("cve,epss,percentile", "cve,score")],
      ["short row", csvFor(DAY_ONE, MODEL, ["CVE-2099-0001,0.1,0.8", "CVE-2099-0002,0.2"])],
      ["duplicate ID", csvFor(DAY_ONE, MODEL, ["CVE-2099-0001,0.1,0.8", "CVE-2099-0001,0.2,0.9"])],
      ["bad CVE ID", csvFor(DAY_ONE, MODEL, ["NOTACVE,0.1,0.8"])],
      ["epss above one", csvFor(DAY_ONE, MODEL, ["CVE-2099-0001,1.5,0.8"])],
      ["negative percentile", csvFor(DAY_ONE, MODEL, ["CVE-2099-0001,0.1,-0.2"])],
      ["non-numeric epss", csvFor(DAY_ONE, MODEL, ["CVE-2099-0001,NaN,0.8"])],
      [
        "header only, no rows",
        `#model_version:${MODEL},score_date:${DAY_ONE}\ncve,epss,percentile`,
      ],
    ];
    for (const [name, input] of cases) {
      expect(() => parseEpssCsv(input), name).toThrowError(EpssImportError);
    }
  });
});

describe("EPSS daily import and history archive", () => {
  it("stores exact decimals with score date and model version", () => {
    const db = makeDatabase();
    try {
      const result = importEpssCsv(db, DAY_ONE_CSV, {
        knownCveIds: ["CVE-2099-0001", "CVE-2099-0002"],
      });
      expect(result).toMatchObject({ scoreDate: DAY_ONE, modelVersion: MODEL, rowCount: 3 });
      expect(result.unmatched).toEqual(["CVE-2099-0003"]);

      const stored = db.handle
        .prepare(
          "SELECT epss, percentile, score_date, model_version FROM epss_daily WHERE cve_id = ?",
        )
        .get("CVE-2099-0001") as {
        epss: string;
        percentile: string;
        score_date: string;
        model_version: string;
      };
      expect(stored).toEqual({
        epss: "0.10",
        percentile: "0.80000",
        score_date: DAY_ONE,
        model_version: MODEL,
      });
      expect(getAcceptedEpssDate(db)).toBe(DAY_ONE);
    } finally {
      db.close();
    }
  });

  it("keeps a real zero known while a missing current row stays unknown", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, DAY_ONE_CSV);
      expect(lookupEpss(db, "CVE-2099-0002")?.epssText).toBe("0");
      expect(lookupEpss(db, "CVE-2099-0099")).toBeUndefined();
    } finally {
      db.close();
    }
  });

  it("archives dated observations and never backfills the current lookup", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, DAY_ONE_CSV);
      importEpssCsv(db, DAY_TWO_CSV);
      expect(getAcceptedEpssDate(db)).toBe(DAY_TWO);
      expect(epssDailyCount(db)).toBe(5);

      const history = getEpssHistory(db, "CVE-2099-0001");
      expect(history.map((row) => row.scoreDate)).toEqual([DAY_ONE, DAY_TWO]);

      // CVE-2099-0002 has a DAY_ONE row but no DAY_TWO row: unknown, not 0.
      expect(lookupEpss(db, "CVE-2099-0002")).toBeUndefined();
      expect(lookupEpss(db, "CVE-2099-0001")?.epssText).toBe("0.18");
    } finally {
      db.close();
    }
  });

  it("reimporting the same file is idempotent", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, DAY_ONE_CSV);
      importEpssCsv(db, DAY_ONE_CSV);
      expect(epssDailyCount(db)).toBe(3);
      expect(getAcceptedEpssDate(db)).toBe(DAY_ONE);
    } finally {
      db.close();
    }
  });

  it("reports unmatched IDs without manufacturing CVE records", () => {
    const db = makeDatabase();
    try {
      const result = importEpssCsv(db, DAY_ONE_CSV, { knownCveIds: ["CVE-2099-0001"] });
      expect(result.unmatched).toEqual(["CVE-2099-0002", "CVE-2099-0003"]);
      const records = db.handle.prepare("SELECT COUNT(*) AS n FROM cve_records").get() as {
        n: number;
      };
      expect(records.n).toBe(0);
    } finally {
      db.close();
    }
  });

  it("a truncated CSV aborts without touching the accepted snapshot", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, DAY_ONE_CSV);
      const truncated = csvFor(DAY_TWO, MODEL, [
        "CVE-2099-0001,0.18,0.85000",
        "CVE-2099-0003,0.12",
      ]);
      expect(() => importEpssCsv(db, truncated)).toThrowError(EpssImportError);

      expect(getAcceptedEpssDate(db)).toBe(DAY_ONE);
      expect(epssDailyCount(db)).toBe(3);
      expect(lookupEpss(db, "CVE-2099-0001")?.epssText).toBe("0.10");
      const failed = db.handle
        .prepare("SELECT status, error FROM sync_runs ORDER BY id DESC LIMIT 1")
        .get() as { status: string; error: string | null };
      expect(failed.status).toBe("failed");
      expect(failed.error).toMatch(/expected 3 columns/);
    } finally {
      db.close();
    }
  });
});

describe("EPSS rising eligibility and exact decimals", () => {
  it("computes percentage-point deltas without binary float error", () => {
    expect(computeDeltaPpText("0.18", "0.10")).toBe("8");
    expect(computeDeltaPpText("0.28", "0.20")).toBe("8");
    expect(computeDeltaPpText("0.1162", "0.10")).toBe("1.62");
  });

  it("requires exact d and d-7 observations under one model", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, csvFor(DAY_SEVEN_BACK, MODEL, ["CVE-2099-0001,0.10,0.80000"]));
      importEpssCsv(db, DAY_TWO_CSV);
      const eligible = checkRisingEligible(db, "CVE-2099-0001", DAY_TWO, DAY_SEVEN_BACK);
      expect(eligible).toEqual({ eligible: true, modelVersion: MODEL, deltaPpText: "8" });

      // Missing d-7 row: ineligible, never zero-filled.
      expect(checkRisingEligible(db, "CVE-2099-0003", DAY_TWO, DAY_SEVEN_BACK).eligible).toBe(
        false,
      );
    } finally {
      db.close();
    }
  });

  it("treats a model transition as ineligible, never a spike", () => {
    const db = makeDatabase();
    try {
      importEpssCsv(db, csvFor(DAY_SEVEN_BACK, MODEL, ["CVE-2099-0001,0.10,0.80000"]));
      importEpssCsv(db, csvFor(DAY_TWO, "v2027.01.01", ["CVE-2099-0001,0.80,0.99000"]));
      const outcome = checkRisingEligible(db, "CVE-2099-0001", DAY_TWO, DAY_SEVEN_BACK);
      expect(outcome.eligible).toBe(false);
      if (!outcome.eligible) {
        expect(outcome.reason).toMatch(/model transition/);
      }
    } finally {
      db.close();
    }
  });
});

describe("EPSS live download", () => {
  it.runIf(process.env.EPSS_LIVE_TEST === "1")(
    "fetches and parses the live current CSV (opt-in, skipped by default)",
    async () => {
      const { fetchEpssCsvText } = await import("../src/lib/epss-import");
      const text = await fetchEpssCsvText();
      const document = parseEpssCsv(text);
      expect(document.rows.length).toBeGreaterThan(0);
    },
  );
});
