import { expect, test } from "@playwright/test";

// Relation graph journey. Deliberately fixture-free: the graph reads whatever
// KEV cohort the shared dev database holds, and other suites swap that file
// wholesale (the server keeps its own handle), so seeded rows are not durable
// here. These tests assert the contract instead: no implicit center, a ranked
// hub landing, and a bipartite attribute view once a record is centered.
test("landing ranks hubs and never pre-fills a center", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph");
  await expect(page.getByTestId("graph-root")).toBeVisible();
  await expect(page.getByTestId("graph-landing")).toBeVisible();
  // No phantom default: the input is empty until the reader chooses.
  await expect(page.getByTestId("graph-focus-input")).toHaveValue("");

  const hubs = page.getByTestId("graph-hubs");
  const empty = page.getByTestId("graph-empty");
  if (await hubs.isVisible()) {
    const firstHub = hubs.locator("li").first();
    await expect(firstHub).toContainText(/CVE-\d{4}-\d+/);
    await expect(firstHub).toContainText("links");
  } else {
    // Honest empty state when the retained cohort has no KEV rows.
    await expect(empty).toContainText("No KEV cohort");
  }
});

test("centering a hub shows grouped shared attributes", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph");
  const hubs = page.getByTestId("graph-hubs");
  if (!(await hubs.isVisible())) {
    test.skip(true, "no KEV cohort in this database");
    return;
  }
  const link = hubs.locator("li a.graph-hub-id").first();
  const cveId = (await link.textContent())?.trim() ?? "";
  expect(cveId).toMatch(/^CVE-\d{4}-\d+/);

  await page.goto(`/graph?focus=${encodeURIComponent(cveId)}`);
  await expect(page.getByTestId("graph-centered")).toBeVisible();
  await expect(page.getByTestId("graph-center-id")).toContainText(cveId);
  await expect(page.getByTestId("graph-focus-input")).toHaveValue("");
  await expect(page.getByTestId("graph-clear")).toBeVisible();

  const columns = page.getByTestId("graph-columns");
  const noLinks = page.getByTestId("graph-no-links");
  if (await columns.isVisible()) {
    // Every group names one shared attribute and at least one other record.
    const firstGroup = columns.locator(".graph-group").first();
    await expect(firstGroup).toContainText(/CVE-\d{4}-\d+/);
  } else {
    await expect(noLinks).toContainText("No labeled links");
  }
});

test("an unknown focus is refused with a message, not a broken graph", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/graph?focus=CVE-1999-0001");
  await expect(page.getByTestId("graph-invalid")).toContainText(
    "not a KEV-listed PUBLISHED record",
  );
});
