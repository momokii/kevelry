import { expect, test } from "@playwright/test";

// Console polish batch: hero update context, filter-summary affordance,
// per-page alignment, custom checkboxes, replay purpose note.
test("overview hero names the snapshot update", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await expect(page.getByTestId("overview-updated")).toContainText("Snapshot updated");
  await expect(page.getByTestId("overview-updated")).toContainText("CVE List");
  await expect(page.getByTestId("overview-updated")).toContainText("KEV");
  await expect(page.getByTestId("overview-updated")).toContainText("EPSS");
});

test("explore filter summary shows affordance and count badge", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  await expect(page.locator(".filter-chevron").first()).toBeVisible();
  await expect(page.locator(".filter-count").first()).toHaveText("none active");

  await page.goto("/explore?severity=critical");
  const badge = page.locator(".filter-count").first();
  await expect(badge).toHaveText("1 active");
  await expect(badge).toHaveClass(/is-active/);
});

test("explore per-page select aligns with the apply button", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  const select = page.getByTestId("explore-limit");
  const apply = page.getByTestId("explore-apply");
  await expect(select).toBeVisible();
  await expect(apply).toBeVisible();
  const gap = await page.evaluate(() => {
    const a = document.querySelector("[data-testid='explore-limit']");
    const b = document.querySelector("[data-testid='explore-apply']");
    if (a === null || b === null) return Number.NaN;
    return Math.abs(a.getBoundingClientRect().bottom - b.getBoundingClientRect().bottom);
  });
  expect(gap).toBeLessThanOrEqual(2);
});

test("explore checkboxes wear the themed control", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  const box = page.getByTestId("explore-severity-critical");
  await expect(box).toBeVisible();
  await expect(box).toHaveCSS("appearance", "none");
});

test("help tooltip floats inside the viewport without pushing content", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/explore");
  const trigger = page.getByTestId("explore-help-severity-trigger");
  const panel = page.getByTestId("explore-help-severity-panel");
  const before = await page.locator(".explore-sidebar").boundingBox();
  await trigger.focus();
  await expect(panel).toBeVisible();
  const box = await panel.boundingBox();
  expect(box === null ? 0 : box.x + box.width).toBeLessThanOrEqual(1280);
  expect(box?.x).toBeGreaterThanOrEqual(0);
  const after = await page.locator(".explore-sidebar").boundingBox();
  expect(after?.height).toEqual(before?.height);
});

test("freshness panel names per-source accepted times", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");
  await expect(page.getByTestId("overview-freshness")).toContainText("accepted");
});

test("replay explains its own purpose", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/replay");
  const explainer = page.getByTestId("replay-explainer");
  await expect(explainer).toBeVisible();
  await expect(explainer).toContainText("What is replay for");
  await expect(explainer).toContainText("KEV");
});
