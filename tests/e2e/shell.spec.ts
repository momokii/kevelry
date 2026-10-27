import { expect, test } from "@playwright/test";

// Rail consistency: the Data-status rows mirror the primary nav rows
// (icon + label + trailing pill, 44px target) and every dropdown wears the
// themed control instead of the native OS select.
test("rail data-status rows match nav rows and dropdowns are themed", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/");

  for (const row of [
    { name: "Source freshness", pill: "status" },
    { name: "Reference", pill: "v1" },
  ]) {
    const link = page.getByRole("link", { name: `${row.name} ${row.pill}` });
    await expect(link).toBeVisible();
    await expect(link.locator("svg").first()).toBeVisible();
    await expect(link.locator(".app-nav-count")).toHaveText(row.pill);
    const box = await link.boundingBox();
    expect(box?.height).toBeGreaterThanOrEqual(44);
  }

  const timezone = page.getByTestId("global-timezone");
  await expect(timezone).toBeVisible();
  await expect(timezone).toHaveCSS("appearance", "none");
  const selectBox = await timezone.boundingBox();
  expect(selectBox?.height).toBeGreaterThanOrEqual(44);
});
