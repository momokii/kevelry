import { expect, test } from "@playwright/test";

const EVIDENCE_DIR =
  "/home/kelanach/Public/main-linux-kelanach/code-berkah-titipan-tuhan/code/personal_prjct/cybersec/cve-injector/.omo/evidence/task-2-cve-change-radar";

const STATE_IDS = [
  "state-masthead-default",
  "state-masthead-current",
  "state-masthead-focus",
  "state-masthead-wrapped",
  "state-masthead-historical",
  "state-masthead-hover",
  "state-search-default",
  "state-search-populated",
  "state-search-focus",
  "state-search-hover",
  "state-search-pending",
  "state-search-invalid",
  "state-search-empty",
  "state-search-error",
  "state-filter-default",
  "state-filter-selected",
  "state-filter-hover",
  "state-filter-focus",
  "state-filter-disabled",
  "state-filter-empty",
  "state-filter-wrapped",
  "state-row-default",
  "state-row-hover",
  "state-row-focus",
  "state-row-long",
  "state-row-missing",
  "state-row-unscored",
  "state-row-unknown",
  "state-row-rejected",
  "state-evidence-default",
  "state-evidence-loading",
  "state-evidence-stale",
  "state-evidence-failed",
  "state-evidence-missing",
  "state-chart-default",
  "state-chart-loading",
  "state-chart-empty",
  "state-chart-unknown",
  "state-chart-correction",
  "state-chart-keyboard",
  "state-chart-error",
  "state-ordering-default",
  "state-ordering-tie",
  "state-ordering-missing",
  "state-ordering-coverage",
  "state-ordering-stale",
  "state-ordering-focus",
  "state-compare-unchanged",
  "state-compare-added",
  "state-compare-removed",
  "state-compare-changed",
  "state-compare-unknown",
  "state-compare-incomparable",
  "state-compare-focus",
  "state-snapshot-default",
  "state-snapshot-focus",
  "state-snapshot-loading",
  "state-snapshot-missing",
  "state-snapshot-expired",
  "state-snapshot-initial",
  "state-snapshot-stale",
  "state-snapshot-disabled",
  "state-notice-default",
  "state-notice-pending",
  "state-notice-applied",
  "state-notice-dismissed",
  "state-notice-focus",
  "state-stress-empty",
  "state-stress-label",
  "state-stress-url",
  "state-stress-zoom",
] as const;

for (const width of [360, 768, 1280]) {
  test(`showcase renders every state at ${width}px without overflow`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/showcase");
    await expect(page.getByTestId("showcase-root")).toBeVisible();

    for (const id of STATE_IDS) {
      await expect(page.getByTestId(id).first(), `${id} at ${width}px`).toBeVisible();
    }

    // Hover states stay rendered while hovered.
    await page.getByTestId("search-hover-action").hover();
    await expect(page.getByTestId("search-hover-action")).toBeVisible();
    await page.getByTestId("filter-hover-chip").first().hover();
    await expect(page.getByTestId("state-filter-hover")).toBeVisible();
    await page.getByTestId("row-hover-action").hover();
    await expect(page.getByTestId("row-hover-action")).toBeVisible();

    // Focus states receive keyboard focus with a visible outline.
    await page.getByTestId("search-focus-input").focus();
    await expect(page.getByTestId("search-focus-input")).toBeFocused();
    const searchOutline = await page
      .getByTestId("search-focus-input")
      .evaluate((el) => getComputedStyle(el).outlineWidth);
    expect(searchOutline, "search input focus outline").not.toBe("0px");

    await page.getByTestId("snapshot-focus-select").focus();
    await expect(page.getByTestId("snapshot-focus-select")).toBeFocused();

    await page.getByTestId("notice-focus-action").focus();
    await expect(page.getByTestId("notice-focus-action")).toBeFocused();

    // Disabled, loading, empty, and error states carry their semantics.
    await expect(page.getByTestId("search-pending-action")).toBeDisabled();
    await expect(page.getByTestId("filter-disabled-chip").first()).toBeDisabled();
    await expect(page.getByTestId("snapshot-disabled-select")).toBeDisabled();
    await expect(page.getByTestId("search-pending-feedback")).toContainText("Searching local snapshots");
    await expect(page.getByTestId("search-empty-feedback")).toContainText("No matches");
    await expect(page.getByTestId("search-error-feedback")).toContainText("Search failed");
    await expect(page.getByTestId("row-missing-title")).toContainText("Description not supplied");
    await expect(page.getByTestId("row-unknown-signals")).toContainText("EPSS unavailable for this snapshot");

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow, `horizontal overflow at ${width}px`).toBeLessThanOrEqual(1);

    await page.screenshot({ path: `${EVIDENCE_DIR}/showcase-${width}.png`, fullPage: true });
  });
}

test("showcase survives content stress, 200% zoom, and reduced motion", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/showcase");

  await expect(page.getByTestId("state-stress-label")).toBeVisible();
  await expect(page.getByTestId("state-stress-url")).toBeVisible();
  await expect(page.getByTestId("stress-url-stress")).toBeVisible();
  await page.getByTestId("state-stress-url").scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${EVIDENCE_DIR}/showcase-stress-1280.png` });

  // 200% zoom reflow: effective CSS viewport of a 1280px window.
  await page.evaluate(() => {
    document.body.style.zoom = "200%";
  });
  const zoomOverflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(zoomOverflow, "horizontal overflow at 200% zoom").toBeLessThanOrEqual(1);
  await page.getByTestId("state-stress-zoom").scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${EVIDENCE_DIR}/showcase-zoom-200.png` });
  await page.evaluate(() => {
    document.body.style.zoom = "";
  });

  // Reduced-motion path: transitions collapse to none.
  await page.emulateMedia({ reducedMotion: "reduce" });
  const transitionDuration = await page
    .getByTestId("search-hover-action")
    .evaluate((el) => getComputedStyle(el).transitionDuration);
  expect(transitionDuration, "reduced-motion transition").toBe("0s");
  await page.screenshot({ path: `${EVIDENCE_DIR}/showcase-reduced-motion.png`, fullPage: true });
});
