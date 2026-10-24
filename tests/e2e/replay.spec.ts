import { expect, test, type Page } from "@playwright/test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";
import {
  RADAR_POLICY_VERSION,
  listCheckpoints,
  replayCheckpoint,
  type RadarViews,
  writeCheckpoint,
} from "../../src/lib/radar";
import {
  A11Y_EVIDENCE_DIR,
  auditReducedMotion,
  auditRoute,
  auditZoomReflow,
  ensureA11yEvidenceDir,
} from "./a11y-audit";

test.describe.configure({ mode: "serial" });

const PROJECT_ROOT = process.cwd();
const SERVER_DATA_DIR = path.resolve(PROJECT_ROOT, process.env.DATA_DIR ?? "./data");
const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-22-cve-change-radar";

const MODEL = "v2026.06.15";
const STAMP = "2026-10-24T00:00:00.000Z";

const ID_KEV = "CVE-2099-2001";
const ID_FORECAST = "CVE-2099-2002";
const ID_SPARSE = "CVE-2099-2003";
const ID_LATE = "CVE-2099-2004";
const ID_CURRENT_ONLY = "CVE-2099-2005";

function utcDay(offsetDays: number): string {
  return new Date(Date.now() - offsetDays * 86_400_000).toISOString().slice(0, 10);
}

const SCORE_DATE = utcDay(3);
const PREV_DATE = utcDay(10);
const PUBLISHED_AT = `${utcDay(10)}T00:00:00.000Z`;
const DATE_A = utcDay(2);
const DATE_B = utcDay(1);
const DATE_EXPIRED = utcDay(45);
const DATE_MISSING = utcDay(5);

const VIEW_SLUGS = [
  "default-priority",
  "known-exploited",
  "highest-forecast",
  "new-critical",
  "rising-forecast",
] as const;

const tempDirs: string[] = [];
let hadServerDb = false;
let serverDbBackup = "";
let expectedA: RadarViews | null = null;
let expectedB: RadarViews | null = null;
let retainedFrom = "";
let retainedTo = "";

function seedRecord(db: CveDatabase, cveId: string): void {
  db.handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      cveId,
      "5.1",
      "PUBLISHED",
      PUBLISHED_AT,
      PUBLISHED_AT,
      `Retained description for ${cveId}`,
      STAMP,
      STAMP,
    );
}

function seedKev(db: CveDatabase, cveId: string, dateAdded: string): void {
  db.handle
    .prepare(
      "INSERT INTO kev_entries (cve_id, date_added, catalog_date, recorded_at) VALUES (?, ?, ?, ?)",
    )
    .run(cveId, dateAdded, `${SCORE_DATE}T00:00:00.000Z`, STAMP);
}

function seedEpss(db: CveDatabase, cveId: string, scoreDate: string, epss: string): void {
  db.handle
    .prepare(
      "INSERT OR REPLACE INTO epss_daily (cve_id, score_date, model_version, epss, percentile) VALUES (?, ?, ?, ?, ?)",
    )
    .run(cveId, scoreDate, MODEL, epss, "0.80000");
}

function seedCvss(db: CveDatabase, cveId: string, baseScore: string): void {
  db.handle
    .prepare(
      "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .run(cveId, "CNA", "3.1", baseScore, "CVSS:3.1/AV:N", 0);
}

function pins(revision: string): {
  cveRevision: string;
  kevCatalogDate: string;
  epssScoreDate: string;
  epssModelVersion: string;
} {
  return {
    cveRevision: revision,
    kevCatalogDate: `${SCORE_DATE}T00:00:00.000Z`,
    epssScoreDate: SCORE_DATE,
    epssModelVersion: MODEL,
  };
}

/** Builds the two-checkpoint plus one-expired replay corpus in a temp DATA_DIR. */
function buildSeededDbFile(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-replay-seed-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });

  seedRecord(db, ID_KEV);
  seedRecord(db, ID_FORECAST);
  seedRecord(db, ID_SPARSE);
  seedKev(db, ID_KEV, utcDay(20));
  seedEpss(db, ID_KEV, SCORE_DATE, "0.42");
  seedEpss(db, ID_KEV, PREV_DATE, "0.10");
  seedEpss(db, ID_FORECAST, SCORE_DATE, "0.31");
  seedEpss(db, ID_FORECAST, PREV_DATE, "0.05");
  seedCvss(db, ID_KEV, "9.8");
  seedCvss(db, ID_FORECAST, "9.1");

  writeCheckpoint(db, {
    checkpointDate: DATE_EXPIRED,
    observedAt: `${DATE_EXPIRED}T12:00:00.000Z`,
    sourcePins: pins("rev-replay-expired"),
  });

  writeCheckpoint(db, {
    checkpointDate: DATE_A,
    observedAt: `${DATE_A}T12:00:00.000Z`,
    sourcePins: pins("rev-replay-a"),
  });

  seedKev(db, ID_FORECAST, DATE_B);
  seedRecord(db, ID_LATE);
  seedEpss(db, ID_LATE, SCORE_DATE, "0.55");
  seedEpss(db, ID_LATE, PREV_DATE, "0.20");
  seedCvss(db, ID_LATE, "9.4");

  writeCheckpoint(db, {
    checkpointDate: DATE_B,
    observedAt: `${DATE_B}T12:00:00.000Z`,
    sourcePins: pins("rev-replay-b"),
  });

  seedRecord(db, ID_CURRENT_ONLY);
  seedEpss(db, ID_CURRENT_ONLY, SCORE_DATE, "0.99");
  seedCvss(db, ID_CURRENT_ONLY, "10.0");

  const asOfDate = new Date().toISOString().slice(0, 10);
  const replayA = replayCheckpoint(db, DATE_A, { asOfDate });
  const replayB = replayCheckpoint(db, DATE_B, { asOfDate });
  if (replayA.status !== "available" || replayB.status !== "available") {
    throw new Error("replay fixtures failed to replay from the seeded corpus");
  }
  expectedA = replayA.manifest.views;
  expectedB = replayB.manifest.views;
  const checkpoints = listCheckpoints(db);
  const first = checkpoints[0];
  const last = checkpoints[checkpoints.length - 1];
  if (first === undefined || last === undefined)
    throw new Error("seeded corpus has no checkpoints");
  retainedFrom = first.checkpointDate;
  retainedTo = last.checkpointDate;

  db.handle.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  db.close();
  return path.join(dir, "cve.db");
}

function clearServerDb(): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    rmSync(path.join(SERVER_DATA_DIR, `cve.db${suffix}`), { force: true });
  }
}

function deployDbFile(sourceFile: string): void {
  mkdirSync(SERVER_DATA_DIR, { recursive: true });
  clearServerDb();
  copyFileSync(sourceFile, path.join(SERVER_DATA_DIR, "cve.db"));
}

test.beforeAll(() => {
  mkdirSync(EVIDENCE_DIR, { recursive: true });
  const current = path.join(SERVER_DATA_DIR, "cve.db");
  hadServerDb = existsSync(current);
  if (hadServerDb) {
    const backupDir = mkdtempSync(path.join(tmpdir(), "cve-replay-backup-"));
    tempDirs.push(backupDir);
    serverDbBackup = path.join(backupDir, "cve.db");
    copyFileSync(current, serverDbBackup);
  }
  deployDbFile(buildSeededDbFile());
});

test.afterAll(() => {
  clearServerDb();
  if (hadServerDb && serverDbBackup !== "") {
    copyFileSync(serverDbBackup, path.join(SERVER_DATA_DIR, "cve.db"));
  }
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
});

async function viewIds(page: Page, slug: string): Promise<string[]> {
  return page.evaluate((viewSlug: string) => {
    const view = document.querySelector(`[data-testid="replay-view-${viewSlug}"]`);
    if (view === null) return [];
    return Array.from(view.querySelectorAll('[data-testid$="-id"]'))
      .map((el) => el.textContent?.trim() ?? "")
      .filter((text) => text.startsWith("CVE-"));
  }, slug);
}

async function expectNoOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow").toBeLessThanOrEqual(1);
}

for (const width of [360, 768, 1280]) {
  test(`replay renders retained checkpoint B at ${width}px`, async ({ page }) => {
    test.slow();
    if (expectedB === null) throw new Error("replay fixtures were not seeded");
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`/replay?date=${DATE_B}`);
    await expect(page.getByTestId("replay-root")).toBeVisible();
    await expect(page.getByTestId("replay-banner")).toContainText(DATE_B);
    await expect(page.getByTestId("replay-banner")).toContainText(
      "Current links are labeled current",
    );
    await expect(page.getByTestId("replay-lists")).toContainText(
      `ranking policy ${RADAR_POLICY_VERSION}`,
    );
    await expect(page.getByTestId("replay-lists-note")).toContainText("rev-replay-b");

    expect(await viewIds(page, "default-priority")).toEqual(expectedB.defaultPriority);
    expect(await viewIds(page, "known-exploited")).toEqual(expectedB.knownExploited);
    expect(await viewIds(page, "highest-forecast")).toEqual(expectedB.highestForecast);
    expect(await viewIds(page, "new-critical")).toEqual(expectedB.newCritical);
    expect(await viewIds(page, "rising-forecast")).toEqual(expectedB.risingForecast);

    await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
    const defaultView = page.getByTestId("replay-view-default-priority");
    const kevView = page.getByTestId("replay-view-known-exploited");
    await expect(defaultView.getByTestId(`replay-item-${ID_SPARSE}-signals`)).toContainText(
      "EPSS unavailable for this snapshot",
    );
    await expect(defaultView.getByTestId(`replay-item-${ID_SPARSE}-signals`)).toContainText(
      "Unscored under this view's policy",
    );
    await expect(defaultView.getByTestId(`replay-item-${ID_SPARSE}-signals`)).toContainText(
      "Not listed in this KEV snapshot",
    );
    await expect(kevView.getByTestId(`replay-item-${ID_KEV}-signals`)).toContainText("KEV listed");
    await expect(kevView.getByTestId(`replay-item-${ID_KEV}-action`)).toContainText("(current)");

    await expect(page.getByTestId(`replay-option-${DATE_A}`)).toHaveCount(1);
    await expect(page.getByTestId(`replay-option-${DATE_B}`)).toHaveCount(1);
    await expect(page.getByTestId(`replay-option-${DATE_EXPIRED}`)).toContainText("(expired)");
    await expect(page.getByTestId("replay-selector-note")).toContainText(retainedFrom);
    await expect(page.getByTestId("replay-selector-note")).toContainText(retainedTo);
    await expect(page.getByTestId("replay-selector-note")).toContainText("History begins");

    await expect(page.getByTestId("replay-ordering")).toContainText(
      `Ranking policy ${RADAR_POLICY_VERSION}`,
    );
    await expect(page.getByTestId("replay-ordering")).toContainText("Coverage:");

    await expectNoOverflow(page);
    await page.screenshot({ path: path.join(EVIDENCE_DIR, `replay-${width}.png`), fullPage: true });
  });
}

test("replay defaults to the newest retained checkpoint", async ({ page }) => {
  await page.setViewportSize({ width: 768, height: 900 });
  await page.goto("/replay");
  await expect(page.getByTestId("replay-banner")).toContainText(retainedTo);
  await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
});

test("selector navigates from checkpoint B back to checkpoint A", async ({ page }) => {
  if (expectedA === null) throw new Error("replay fixtures were not seeded");
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/replay?date=${DATE_B}`);
  await page.getByTestId("replay-selector-select").selectOption(DATE_A);
  await page.getByTestId("replay-selector-submit").click();
  await expect(page.getByTestId("replay-banner")).toContainText(DATE_A);
  await expect(page.getByTestId("replay-lists-note")).toContainText("rev-replay-a");
  expect(await viewIds(page, "known-exploited")).toEqual(expectedA.knownExploited);
  expect(await viewIds(page, "highest-forecast")).toEqual(expectedA.highestForecast);
  await expect(page.getByTestId(`replay-item-${ID_LATE}`)).toHaveCount(0);
  await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
});

test("expired selection renders unavailable with reason, never current data", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/replay?date=${DATE_EXPIRED}`);
  await expect(page.getByTestId("replay-banner")).toContainText(DATE_EXPIRED);
  await expect(page.getByTestId("replay-unavailable")).toBeVisible();
  await expect(page.getByTestId("replay-unavailable-reason")).toContainText("expired");
  await expect(page.getByTestId("replay-unavailable-guarantee")).toContainText(
    "Current data is never substituted",
  );
  for (const slug of VIEW_SLUGS) {
    await expect(page.getByTestId(`replay-view-${slug}`)).toHaveCount(0);
  }
  await expect(page.getByTestId(`replay-item-${ID_KEV}`)).toHaveCount(0);
  await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
  await expectNoOverflow(page);
  await page.screenshot({
    path: path.join(EVIDENCE_DIR, "replay-expired-1280.png"),
    fullPage: true,
  });
});

test("missing date renders unavailable without substituting current data", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/replay?date=${DATE_MISSING}`);
  await expect(page.getByTestId("replay-banner")).toContainText(DATE_MISSING);
  await expect(page.getByTestId("replay-unavailable-reason")).toContainText(
    "no checkpoint retained",
  );
  await expect(page.getByTestId("replay-unavailable-guarantee")).toContainText(
    "Current data is never substituted",
  );
  await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
});

test("model-changed renders unavailable with reason", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`/replay?date=${DATE_B}&model=v0000.00.00`);
  await expect(page.getByTestId("replay-banner")).toContainText(DATE_B);
  await expect(page.getByTestId("replay-model-changed")).toBeVisible();
  await expect(page.getByTestId("replay-model-changed-reason")).toContainText("model-changed");
  await expect(page.getByTestId(`replay-item-${ID_KEV}`)).toHaveCount(0);
  await expect(page.getByTestId(`replay-item-${ID_CURRENT_ONLY}`)).toHaveCount(0);
});

test("replay passes the task-24 accessibility audit", async ({ page }) => {
  ensureA11yEvidenceDir();
  await auditRoute(page, { route: `/replay?date=${DATE_B}`, name: "replay", maxLiveRegions: 1 });

  await expect(page.getByTestId("replay-selector-select")).toBeVisible();
  await page.getByTestId("replay-selector-submit").focus();
  await expect(page.getByTestId("replay-selector-submit")).toBeFocused();
  await page.keyboard.press("Tab");
  await page.screenshot({ path: `${A11Y_EVIDENCE_DIR}/replay-focus-1280.png`, fullPage: true });

  await auditZoomReflow(page, "replay", `${A11Y_EVIDENCE_DIR}/replay-zoom-200.png`);
  await auditReducedMotion(page, "replay", `${A11Y_EVIDENCE_DIR}/replay-reduced-motion.png`);
});
