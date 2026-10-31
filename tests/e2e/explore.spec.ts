import { expect, test, type Page } from "@playwright/test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { openDatabase, type CveDatabase } from "../../src/lib/db";

import {
  A11Y_EVIDENCE_DIR,
  auditReducedMotion,
  auditRoute,
  auditZoomReflow,
  ensureA11yEvidenceDir,
} from "./a11y-audit";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-19-cve-change-radar";

const SEVERITY_BANDS = ["critical", "high", "medium", "low", "none", "legacy", "unknown"] as const;

async function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

for (const width of [360, 768, 1280]) {
  test(`explore renders filters, ordering note, and honest states at ${width}px`, async ({
    page,
  }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
    await expect(page.getByTestId("explore-root")).toBeVisible();
    await expect(page.getByTestId("explore-title")).toContainText("Find the CVE cohort");
    await expect(page.getByTestId("explore-filters")).toBeVisible();
    await expect(page.getByTestId("explore-query")).toBeVisible();
    await expect(page.getByTestId("explore-submit")).toBeVisible();

    for (const band of COHORT_SEVERITY_BANDS) {
      await expect(
        page.getByTestId(`explore-severity-${band}`),
        `${band} chip at ${width}px`,
      ).toBeVisible();
    }
    await expect(page.getByTestId("explore-severity-critical")).not.toBeChecked();
    await expect(page.getByText("Critical · 9.0–10.0").first()).toBeVisible();
    await expect(page.getByText("Legacy · v2 only").first()).toBeVisible();
    await expect(page.getByText("Unscored · no CNA metric").first()).toBeVisible();

    await expect(page.getByTestId("explore-kev-all")).toBeVisible();
    await expect(page.getByTestId("explore-kev-only")).toBeVisible();
    await expect(page.getByTestId("explore-kev-excluded")).toBeVisible();
    await expect(page.getByTestId("explore-epss-all")).toBeVisible();
    await expect(page.getByTestId("explore-epss-present")).toBeVisible();
    await expect(page.getByTestId("explore-epss-absent")).toBeVisible();
    await expect(page.getByTestId("explore-date-start")).toBeVisible();
    await expect(page.getByTestId("explore-date-end")).toBeVisible();
    await expect(page.getByTestId("explore-limit")).toBeVisible();
    await expect(page.getByTestId("explore-apply")).toBeVisible();
    await expect(page.getByTestId("explore-clear")).toBeVisible();

    await expect(page.getByTestId("explore-results")).toBeVisible();
    const listVisible = await page.getByTestId("explore-list").isVisible();
    if (listVisible) {
      await expect(page.getByTestId("explore-ordering")).toBeVisible();
      await expect(page.getByTestId("explore-coverage")).toContainText("Matching cohort:");
      await expect(page.getByTestId("explore-coverage-bands")).toContainText("By severity band:");
      const firstRow = page.getByTestId("explore-row").first();
      await expect(firstRow.getByTestId("explore-row-id")).toContainText(/CVE-/);
      await expect(firstRow.getByTestId("explore-row-excerpt")).not.toBeEmpty();
      await expect(firstRow.getByTestId("explore-row-signals")).not.toBeEmpty();
      await expect(firstRow.getByTestId("explore-row-dates")).not.toBeEmpty();
      const href = await firstRow.getByTestId("explore-row-action").getAttribute("href");
      expect(href, "official-record link").toMatch(/^https:\/\/www\.cve\.org\/CVERecord\?id=CVE-/);
      await expect(page.getByTestId("explore-page-count")).toContainText(
        /Showing \d+ to \d+ of \d+/,
      );
    } else {
      const emptyVisible = await page.getByTestId("explore-empty").isVisible();
      const unavailableVisible = await page.getByTestId("explore-unavailable").isVisible();
      expect(emptyVisible || unavailableVisible, "honest empty or unavailable state").toBe(true);
      if (emptyVisible) {
        await expect(page.getByTestId("explore-empty")).toContainText(
          /No (matches|published records)/,
        );
      } else {
        await expect(page.getByTestId("explore-unavailable")).toContainText("Snapshot unavailable");
      }
      await expect(page.getByTestId("explore-page-count")).toBeVisible();
    }

    await page.getByTestId("explore-query").focus();
    await expect(page.getByTestId("explore-query")).toBeFocused();
    const outline = await page
      .getByTestId("explore-query")
      .evaluate((el) => getComputedStyle(el).outlineWidth);
    expect(outline, "query input focus outline").not.toBe("0px");

    const over = await horizontalOverflow(page);
    expect(over, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/explore-${width}.png`, fullPage: true });
  });
}

test("explore filters are reachable and operable by keyboard alone", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
  await expect(page.getByTestId("explore-filters")).toBeVisible();

  await page.getByTestId("explore-query").focus();
  await page.keyboard.type("buffer overflow", { delay: 10 });
  await expect(page.getByTestId("explore-query")).toHaveValue("buffer overflow");

  const seen = new Set<string>();
  for (let step = 0; step < 40; step += 1) {
    const id = await page.evaluate(() => {
      const active = document.activeElement;
      return active instanceof HTMLElement ? (active.getAttribute("data-testid") ?? "") : "";
    });
    if (id !== "") seen.add(id);
    if (
      seen.has("explore-severity-critical") &&
      seen.has("explore-kev-all") &&
      seen.has("explore-apply")
    )
      break;
    await page.keyboard.press("Tab");
  }
  expect(seen.has("explore-severity-critical"), "severity chip tab-reachable").toBe(true);
  expect(seen.has("explore-kev-all"), "KEV group tab-reachable").toBe(true);
  expect(seen.has("explore-apply"), "apply action tab-reachable").toBe(true);

  await page.getByTestId("explore-severity-critical").focus();
  await expect(page.getByTestId("explore-severity-critical")).toBeFocused();
  await page.keyboard.press("Space");
  await expect(page.getByTestId("explore-severity-critical")).toBeChecked();
  await page.keyboard.press("Space");
  await expect(page.getByTestId("explore-severity-critical")).not.toBeChecked();

  // Native radio pattern: Tab lands on the checked member, arrows move within the group.
  await page.getByTestId("explore-kev-all").focus();
  await expect(page.getByTestId("explore-kev-all")).toBeFocused();
  await page.keyboard.press("ArrowRight");
  await expect(page.getByTestId("explore-kev-only")).toBeFocused();
  await expect(page.getByTestId("explore-kev-only")).toBeChecked();
  const chipOutline = await page
    .getByTestId("explore-kev-only")
    .evaluate((el) => getComputedStyle(el).outlineWidth);
  expect(chipOutline, "filter focus outline").not.toBe("0px");

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-keyboard-1280.png`, fullPage: true });
});

test("explore names invalid filters and keeps typed text", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });

  await page.goto("/explore?dateStart=2026-10-22&dateEnd=2026-10-20");
  await expect(page.getByTestId("explore-invalid")).toContainText("earlier");
  await expect(page.getByTestId("explore-date-start")).toHaveValue("2026-10-22");
  await expect(page.getByTestId("explore-date-end")).toHaveValue("2026-10-20");

  await page.goto("/explore?severity=bogus");
  await expect(page.getByTestId("explore-invalid")).toContainText("Unknown severity band");

  await page.goto("/explore?limit=999");
  await expect(page.getByTestId("explore-invalid")).toContainText("integer");

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-invalid-1280.png`, fullPage: true });
});

test("explore renders hostile input inert without breaking layout", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
  const hostile = "<script>window.__xss=1</script><img src=x onerror=window.__xss=2>";
  await page.goto(`/explore?${new URLSearchParams({ q: hostile }).toString()}`);

  await expect(page.getByTestId("explore-title")).toContainText("Find the CVE cohort");
  await expect(page.getByTestId("explore-query")).toHaveValue(hostile);
  const executed = await page.evaluate(() => (window as unknown as { __xss?: number }).__xss);
  expect(executed, "hostile script must not execute").toBeUndefined();
  expect(await page.locator("script[src='x']").count(), "no injected elements").toBe(0);

  const over = await horizontalOverflow(page);
  expect(over, "horizontal overflow with hostile input at 360px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-hostile-360.png`, fullPage: true });
});

test("explore survives long vendor-style labels and unbroken strings", async ({ page }) => {
  const longLabel = "Vendor label with a forty-character demonstration string";
  const unbroken = `https://www.cve.org/CVERecord?id=CVE-2026-1234${"a".repeat(120)}`;
  await page.setViewportSize({ width: 360, height: 900 });
  await page.goto(`/explore?${new URLSearchParams({ q: `${longLabel} ${unbroken}` }).toString()}`);

  await expect(page.getByTestId("explore-root")).toBeVisible();
  await expect(page.getByTestId("explore-query")).toHaveValue(`${longLabel} ${unbroken}`);
  const over360 = await horizontalOverflow(page);
  expect(over360, "horizontal overflow with long labels at 360px").toBeLessThanOrEqual(1);

  await page.setViewportSize({ width: 1280, height: 900 });
  const over1280 = await horizontalOverflow(page);
  expect(over1280, "horizontal overflow with long labels at 1280px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/explore-stress-360.png`, fullPage: true });
});

test("explore passes the task-24 accessibility audit", async ({ page }) => {
  ensureA11yEvidenceDir();
  await auditRoute(page, { route: "/explore", name: "explore", maxLiveRegions: 2 });

  await expect(page.getByTestId("explore-filters")).toBeVisible();
  await page.getByTestId("explore-query").focus();
  await page.keyboard.press("Tab");
  const afterSearch = await page.evaluate(() =>
    document.activeElement instanceof HTMLElement
      ? (document.activeElement.getAttribute("data-testid") ?? "")
      : "",
  );
  expect(afterSearch, "tab order leaves the search box").not.toBe("explore-query");
  await page.screenshot({ path: `${A11Y_EVIDENCE_DIR}/explore-focus-1280.png`, fullPage: true });

  await auditZoomReflow(page, "explore", `${A11Y_EVIDENCE_DIR}/explore-zoom-200.png`);
  await auditReducedMotion(page, "explore", `${A11Y_EVIDENCE_DIR}/explore-reduced-motion.png`);
});

const SERVER_DATA_DIR = path.resolve(process.cwd(), process.env.DATA_DIR ?? "./data");
const FIXTURE_STAMP = "2026-10-24T00:00:00.000Z";
const fixtureDirs: string[] = [];
let hadServerDb = false;
let serverDbBackup = "";

function fixtureDay(daysAgo: number): string {
  return new Date(Date.now() - daysAgo * 86_400_000).toISOString().slice(0, 10);
}

function insertFixture(
  db: CveDatabase,
  id: string,
  published: string | null,
  score: string | null,
  version: string,
  kev: boolean,
  epss: string | null,
  vendor: string | null = null,
  product: string | null = null,
): void {
  db.handle
    .prepare(
      "INSERT INTO cve_records (cve_id, data_version, state, date_published, date_updated, " +
        "title, description, description_lang, source_revision, created_at, updated_at) " +
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .run(
      id,
      "5.1",
      "PUBLISHED",
      published,
      published,
      `Fixture record ${id}`,
      `Description for ${id}`,
      "en",
      "rev-explore-fixture",
      FIXTURE_STAMP,
      FIXTURE_STAMP,
    );
  if (score !== null) {
    db.handle
      .prepare(
        "INSERT INTO cvss_metrics (cve_id, origin, version, base_score, vector, source_order) " +
          "VALUES (?, 'CNA', ?, ?, 'CVSS:3.1/AV:N', 0)",
      )
      .run(id, version, score);
  }
  if (kev) {
    db.handle
      .prepare(
        "INSERT INTO kev_entries (cve_id, date_added, catalog_date, vendor_project, product, recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(id, `${fixtureDay(8)}T00:00:00.000Z`, fixtureDay(9), vendor, product, FIXTURE_STAMP);
  }
  if (epss !== null) {
    db.handle
      .prepare(
        "INSERT INTO epss_daily (cve_id, score_date, model_version, epss, percentile) " +
          "VALUES (?, ?, 'v4', ?, '0.9000')",
      )
      .run(id, fixtureDay(1), epss);
  }
}

function buildExploreSeedDbFile(): string {
  const dir = mkdtempSync(path.join(tmpdir(), "cve-explore-seed-"));
  fixtureDirs.push(dir);
  const db = openDatabase({ dataDir: dir });
  db.runBoundedWrite(() => {
    insertFixture(
      db,
      "CVE-2099-1001",
      `${fixtureDay(5)}T12:00:00.000Z`,
      "9.8",
      "3.1",
      true,
      "0.7200",
      "DemoVendor",
      "DemoOS",
    );
    insertFixture(
      db,
      "CVE-2099-1002",
      `${fixtureDay(10)}T12:00:00.000Z`,
      "8.1",
      "3.1",
      false,
      "0.3300",
    );
    insertFixture(
      db,
      "CVE-2099-1003",
      `${fixtureDay(35)}T12:00:00.000Z`,
      "5.0",
      "3.1",
      false,
      null,
    );
    insertFixture(
      db,
      "CVE-2099-1004",
      `${fixtureDay(65)}T12:00:00.000Z`,
      "2.0",
      "3.1",
      false,
      null,
    );
    insertFixture(
      db,
      "CVE-2099-1005",
      `${fixtureDay(95)}T12:00:00.000Z`,
      "0.0",
      "3.1",
      false,
      null,
    );
    insertFixture(
      db,
      "CVE-2099-1006",
      `${fixtureDay(125)}T12:00:00.000Z`,
      "5.0",
      "2.0",
      false,
      null,
    );
    insertFixture(
      db,
      "CVE-2099-1007",
      `${fixtureDay(155)}T12:00:00.000Z`,
      null,
      "3.1",
      false,
      null,
    );
    insertFixture(db, "CVE-2099-1008", null, "7.5", "3.1", false, null);
  });
  const file = path.join(dir, "cve.db");
  db.close();
  return file;
}

function clearServerDb(): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    rmSync(path.join(SERVER_DATA_DIR, `cve.db${suffix}`), { force: true });
  }
}

function deploySeed(): void {
  mkdirSync(SERVER_DATA_DIR, { recursive: true });
  const current = path.join(SERVER_DATA_DIR, "cve.db");
  hadServerDb = existsSync(current);
  if (hadServerDb) {
    const backupDir = mkdtempSync(path.join(tmpdir(), "cve-explore-backup-"));
    fixtureDirs.push(backupDir);
    serverDbBackup = path.join(backupDir, "cve.db");
    copyFileSync(current, serverDbBackup);
  }
  clearServerDb();
  copyFileSync(buildExploreSeedDbFile(), path.join(SERVER_DATA_DIR, "cve.db"));
}

function restoreSeed(): void {
  clearServerDb();
  if (hadServerDb && serverDbBackup !== "") {
    copyFileSync(serverDbBackup, path.join(SERVER_DATA_DIR, "cve.db"));
  }
  while (fixtureDirs.length > 0) {
    const dir = fixtureDirs.pop() as string;
    rmSync(dir, { recursive: true, force: true });
  }
}

const COHORT_SEVERITY_BANDS = [
  "critical",
  "high",
  "medium",
  "low",
  "none",
  "legacy",
  "unknown",
] as const;

async function cohortHorizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
}

test.describe("cohort visualization", () => {
  test.beforeAll(() => {
    deploySeed();
  });

  test.afterAll(() => {
    restoreSeed();
  });

  test("explore filter help is keyboard-operable and supplementary", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");

    for (const name of ["date", "severity", "kev", "epss", "limit"] as const) {
      const trigger = page.getByTestId(`explore-help-${name}-trigger`);
      const panel = page.getByTestId(`explore-help-${name}-panel`);
      await expect(trigger, `${name} help trigger visible`).toBeVisible();
      await trigger.focus();
      await expect(trigger, `${name} help trigger focused`).toBeFocused();
      await page.keyboard.press("Enter");
      await expect(panel, `${name} help panel opens by keyboard`).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(panel, `${name} help panel closes on Escape`).toBeHidden();
    }

    const panelText = await page.getByTestId("explore-help-severity-panel").textContent();
    expect(panelText ?? "").toContain("primary CNA");
  });

  test("vendor filter narrows the cohort to KEV-labeled records", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
    await page.getByTestId("explore-vendor").fill("demovendor");
    await page.getByTestId("explore-vendor").press("Enter");
    await expect(page).toHaveURL(/vendor=demovendor/);
    await expect(page.getByTestId("explore-cohort-headline")).toContainText(
      "1 matching published records",
    );
    const ids = await page
      .getByTestId("explore-row")
      .getByTestId("explore-row-id")
      .allTextContents();
    expect(ids).toEqual(["CVE-2099-1001"]);
  });

  test("changing a severity checkbox updates the URL and the cohort chart", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
    await expect(page.getByTestId("explore-cohort")).toBeVisible();

    const before = await page.getByTestId("explore-cohort-headline").textContent();
    expect(before ?? "").toMatch(/matching published records/);

    const critical = page.getByTestId("explore-severity-critical");
    await critical.scrollIntoViewIfNeeded();
    await critical.check();
    await expect(page).toHaveURL(/severity=critical/);
    await expect(page.getByTestId("explore-severity-critical")).toBeChecked();

    await expect(page.getByTestId("explore-cohort")).toBeVisible();
    const headline = await page.getByTestId("explore-cohort-headline").textContent();
    expect(headline ?? "").toMatch(/matching published records/);
    const criticalSegment = await page
      .getByTestId("explore-cohort-severity-critical")
      .textContent();
    expect(criticalSegment ?? "").not.toBe("");
    for (const band of COHORT_SEVERITY_BANDS) {
      await expect(
        page.getByTestId(`explore-cohort-severity-${band}`),
        `severity segment ${band} visible after filter change`,
      ).toBeVisible();
    }
  });

  test("cohort segments and monthly bars preserve the other filters", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto("/explore?kev=only&epss=present");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
    await expect(page.getByTestId("explore-cohort")).toBeVisible();

    const severityHref = await page
      .getByTestId("explore-cohort-severity-high")
      .getAttribute("href");
    expect(severityHref ?? "", "severity link keeps kev and epss").toMatch(/kev=only/);
    expect(severityHref ?? "", "severity link keeps kev and epss").toMatch(/epss=present/);
    expect(severityHref ?? "", "severity link switches the band").toMatch(/severity=high/);

    const monthLinks = page.locator('[data-testid^="explore-cohort-month-"]');
    const monthCount = await monthLinks.count();
    if (monthCount > 0) {
      const firstHref = await monthLinks.first().getAttribute("href");
      expect(firstHref ?? "", "month link keeps kev").toMatch(/kev=only/);
      expect(firstHref ?? "", "month link keeps epss").toMatch(/epss=present/);
      expect(firstHref ?? "", "month link sets a month range").toMatch(/dateStart=\d{4}-\d{2}-01/);
      expect(firstHref ?? "", "month link sets a month range").toMatch(/dateEnd=\d{4}-\d{2}-01/);

      const title = await monthLinks.first().getAttribute("title");
      expect(title ?? "", "month tooltip names the denominator").toMatch(/matching records/);
      const label = await monthLinks.first().getAttribute("aria-label");
      expect(label ?? "", "month link has an accessible name").toContain("Show only");

      await monthLinks.first().focus();
      await expect(monthLinks.first(), "month bar keyboard-focusable").toBeFocused();
      const outline = await monthLinks.first().evaluate((el) => getComputedStyle(el).outlineWidth);
      expect(outline, "month bar focus outline").not.toBe("0px");
    }

    const over = await cohortHorizontalOverflow(page);
    expect(over, "no horizontal page overflow with cohort charts").toBeLessThanOrEqual(1);
  });

  test("cohort visualization stays readable at 360px", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 900 });
    await page.goto("/explore");
    await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
    await expect(page.getByTestId("explore-cohort")).toBeVisible();
    await expect(page.getByTestId("explore-cohort-headline")).toContainText(
      "matching published records",
    );

    const over = await cohortHorizontalOverflow(page);
    expect(over, "horizontal overflow at 360px").toBeLessThanOrEqual(1);
  });
});

test("date presets apply a UTC range and the filter rail scrolls independently", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  await expect(page.getByTestId("explore-filters")).toHaveAttribute("data-hydrated", "true");
  const scrollable = await page.locator(".explore-sidebar").evaluate((el) => ({
    overflow: getComputedStyle(el).overflowY,
    scrollHeight: el.scrollHeight,
    clientHeight: el.clientHeight,
  }));
  expect(scrollable.overflow).toBe("auto");
  expect(scrollable.scrollHeight).toBeGreaterThan(scrollable.clientHeight);
  await page.getByTestId("explore-preset-30").click();
  await expect(page).toHaveURL(/dateStart=\d{4}-\d{2}-\d{2}/);
  await expect(page).toHaveURL(/dateEnd=\d{4}-\d{2}-\d{2}/);
  await expect(page.getByTestId("explore-date-start")).not.toHaveValue("");
});
