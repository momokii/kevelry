// Methodology and data-status journey (plan todo 23). Deploys a deterministic
// invented corpus (CVE-2099 IDs, relative dates so the suite stays green) to
// the dev server DATA_DIR, with a failed KEV feed on top of an older success:
// the documented stale warning must render with last-known-good data, not a
// frozen page. Every required reuse notice from docs/research/SOURCES.md is
// asserted by testid and key phrase, so deleting any notice fails this spec.
// Serial: every test shares the one server DATA_DIR.

import { expect, test } from "@playwright/test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openDatabase } from "../../src/lib/db";
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
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-23-cve-change-radar";

const STAMP = "2026-10-24T00:00:00.000Z";

const tempDirs: string[] = [];
let hadServerDb = false;
let serverDbBackup = "";

function dayAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
}

function isoDayAgo(days: number, time = "12:00:00.000Z"): string {
  return `${dayAgo(days)}T${time}`;
}

/** Seeded DB: one published record plus a failed KEV feed over an older success. */
function buildSeededDbFile(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-methodology-seed-"));
  tempDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  const epssDate = dayAgo(10);
  db.runBoundedWrite(() => {
    db.handle
      .prepare(
        "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
          "title, description, description_lang, source_revision, created_at, updated_at) " +
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        "CVE-2099-2301",
        "5.1",
        "PUBLISHED",
        isoDayAgo(5),
        isoDayAgo(5),
        "Supplied CNA title: overflow in demo service.",
        "Supplied description for CVE-2099-2301 with enough detail to render.",
        "en",
        "rev-fixture-2301",
        STAMP,
        STAMP,
      );
    const seedSync = db.handle.prepare(
      "INSERT INTO sync_runs (source, started_at, finished_at, status, revision, content_hash, error) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    seedSync.run(
      "cve",
      isoDayAgo(10, "08:00:00.000Z"),
      isoDayAgo(10, "08:00:00.000Z"),
      "succeeded",
      "rev-fixture-2301",
      null,
      null,
    );
    seedSync.run(
      "kev",
      isoDayAgo(11, "08:00:00.000Z"),
      isoDayAgo(11, "08:00:00.000Z"),
      "succeeded",
      dayAgo(11),
      null,
      null,
    );
    seedSync.run(
      "kev",
      isoDayAgo(9, "09:12:00.000Z"),
      isoDayAgo(9, "09:12:00.000Z"),
      "failed",
      null,
      null,
      "catalog fetch failed: HTTP 503",
    );
    seedSync.run(
      "epss",
      isoDayAgo(10, "08:30:00.000Z"),
      isoDayAgo(10, "08:30:00.000Z"),
      "succeeded",
      `${epssDate}@v4`,
      null,
      null,
    );
  });
  db.checkpointStatus();
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
    const backupDir = mkdtempSync(path.join(tmpdir(), "cve-methodology-backup-"));
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

for (const width of [360, 768, 1280]) {
  test(`methodology renders every section at ${width}px without overflow`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/methodology");

    await expect(page.getByTestId("methodology-root")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Methodology and data status", exact: true }),
    ).toBeVisible();

    const masthead = page.getByTestId("methodology-masthead");
    await expect(masthead.getByText("Method (current)")).toHaveAttribute("aria-current", "page");

    await expect(page.getByTestId("methodology-signals")).toContainText("supplied severity");
    await expect(page.getByTestId("methodology-ordering-default")).toContainText(
      "KEV member before not listed",
    );
    await expect(page.getByTestId("methodology-ordering-known-exploited")).toContainText(
      "KEV dateAdded descending",
    );
    await expect(page.getByTestId("methodology-ordering-highest-forecast")).toContainText(
      "Raw EPSS probability descending",
    );
    await expect(page.getByTestId("methodology-ordering-new-critical")).toContainText(
      "[T - 30d, T)",
    );
    await expect(page.getByTestId("methodology-ordering-rising-forecast")).toContainText(
      "delta percentage-points descending",
    );
    await expect(page.getByTestId("methodology-sources")).toContainText(
      "accepted local snapshots only",
    );
    await expect(page.getByTestId("methodology-gaps")).toContainText("Not promised");
    await expect(page.getByTestId("methodology-checklist")).toContainText("Before release");

    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/methodology-${width}.png`, fullPage: true });
  });
}

test("every required reuse notice appears verbatim", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/methodology");

  await expect(page.getByTestId("notice-cve")).toContainText("reproduce MITRE");
  await expect(page.getByTestId("notice-cve")).toContainText("no-charge reuse, not CC0");
  await expect(page.getByTestId("notice-kev")).toContainText("Creative Commons 0 1.0");
  await expect(page.getByTestId("notice-kev")).toContainText("any lawful manner");
  await expect(page.getByTestId("notice-kev-marks")).toContainText("nor implied endorsement");
  await expect(page.getByTestId("notice-epss")).toContainText(
    "free of charge, with no registration required",
  );
  await expect(page.getByTestId("notice-epss")).toContainText("vulnerability disclosure");
  await expect(page.getByTestId("notice-epss-attribution")).toContainText("attribution");
  await expect(page.getByTestId("notice-first-clarification")).toContainText("clarify FIRST");
  await expect(page.getByTestId("notice-not-legal-advice")).toContainText("not legal advice");
  await expect(page.getByTestId("notice-recheck")).toContainText("Recheck terms before launch");
});

test("failed KEV feed renders the documented stale warning with last-known-good data", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/methodology");

  await expect(page.getByTestId("methodology-health-cve")).toContainText("Stale");
  await expect(page.getByTestId("methodology-health-cve-detail")).toContainText(
    "more than 3 hours old",
  );
  await expect(page.getByTestId("methodology-health-kev")).toContainText("Source failed");
  await expect(page.getByTestId("methodology-health-kev-detail")).toContainText("HTTP 503");
  await expect(page.getByTestId("methodology-health-kev-detail")).toContainText("last-known-good");
  await expect(page.getByTestId("methodology-health-kev-detail")).toContainText(
    "never freezes the other",
  );
  await expect(page.getByTestId("methodology-health-epss")).toContainText("Stale");
  await expect(page.getByTestId("methodology-health-epss-detail")).toContainText(
    "older than 2 UTC calendar days",
  );
  await expect(page.getByTestId("methodology-health-epss-detail")).toContainText(
    "never relabeled as current-day forecasts",
  );
  await expect(page.getByTestId("methodology-gaps")).toContainText("1 published");

  await page.screenshot({
    path: `${EVIDENCE_DIR}/methodology-failed-feed-1280.png`,
    fullPage: true,
  });
});

test("methodology passes the task-24 accessibility audit", async ({ page }) => {
  ensureA11yEvidenceDir();
  await auditRoute(page, { route: "/methodology", name: "methodology", maxLiveRegions: 1 });

  const healthSymbols = await page
    .locator('[data-testid="methodology-health"] .ledger-evidence-symbol')
    .count();
  expect(healthSymbols, "health states carry text symbols, not color alone").toBeGreaterThanOrEqual(3);

  await page.locator(".ledger-skip-link").focus();
  await expect(page.locator(".ledger-skip-link")).toBeFocused();
  await page.screenshot({ path: `${A11Y_EVIDENCE_DIR}/methodology-focus-1280.png`, fullPage: true });

  await auditZoomReflow(page, "methodology", `${A11Y_EVIDENCE_DIR}/methodology-zoom-200.png`);
  await auditReducedMotion(
    page,
    "methodology",
    `${A11Y_EVIDENCE_DIR}/methodology-reduced-motion.png`,
  );
});
