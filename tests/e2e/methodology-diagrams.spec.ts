// Methodology diagrams journey (unexecuted by default: the orchestrator owns
// central QA, so this spec is recorded but not run here). Asserts the three
// figures are visible with accessible names and that nothing overflows at
// 360px. Serial: shares the one server DATA_DIR like methodology.spec.ts.

import { expect, test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test("diagrams are visible, named, and overflow-free at 360px", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
  await page.goto("/methodology");

  const nav = page.getByTestId("methodology-anchor-nav");
  await expect(nav).toBeVisible();
  for (const name of ["Signals", "Pipeline", "Ordering", "Sources", "Notices", "Gaps", "Status"]) {
    await expect(nav.getByRole("link", { name })).toBeVisible();
  }

  const pipeline = page.getByTestId("methodology-pipeline");
  await expect(pipeline).toBeVisible();
  await expect(pipeline).toHaveAccessibleName(/ingestion/i);
  await expect(page.getByTestId("methodology-pipeline-failure")).toContainText("last-known-good");

  const flow = page.getByTestId("methodology-ordering-flow");
  await expect(flow).toBeVisible();
  await expect(flow).toContainText("KEV member before not listed");
  await expect(page.getByTestId("methodology-ordering-modes")).toContainText(
    "No composite score is computed",
  );

  const signals = page.getByTestId("methodology-signals-diagram");
  await expect(signals).toBeVisible();
  await expect(page.getByTestId("methodology-signals-convergence")).toContainText(
    "never multiplied",
  );

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow at 360px").toBeLessThanOrEqual(1);
});

test("pipeline, coverage, and worked example explain the model", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/methodology");
  await expect(page.getByTestId("methodology-coverage-diagram")).toBeVisible();
  await expect(page.getByTestId("methodology-scoring-example")).toBeVisible();
  await page.getByTestId("methodology-pipeline-stage-4").click();
  await expect(page.getByTestId("methodology-pipeline")).toContainText(
    "Atomic publish and manifest",
  );
  await expect(page.getByTestId("methodology-pipeline-failure")).toContainText("last-known-good");
});
