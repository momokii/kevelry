// Browsable API docs journey (task 45). The page reads openapi/v1.yaml at
// build time, so no DB seeding is needed: assert the table renders every
// spec path+method, every endpoint carries a copy-paste example, and the
// masthead API link navigates from the home page.

import { expect, test } from "@playwright/test";

const PROJECT_ROOT = process.cwd();
const EVIDENCE_DIR = `${PROJECT_ROOT}/.omo/evidence/task-45-api-docs`;

const EXPECTED_ROWS = [
  "get-api-v1-cves",
  "get-api-v1-cves-cveid",
  "get-api-v1-search",
  "get-api-v1-priority-listname",
  "get-api-v1-radar",
  "get-api-v1-replay",
  "get-api-v1-replay-checkpoints",
  "get-api-v1-overview",
  "get-api-v1-status",
  "get-api-v1-health",
];

test("api-docs renders the endpoints table with an example per endpoint", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/api-docs");

  await expect(page.getByTestId("api-docs-root")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Public API v1", exact: true })).toBeVisible();

  const masthead = page.getByTestId("api-docs-masthead");
  await expect(masthead.getByRole("link", { name: /API/ })).toHaveAttribute("aria-current", "page");

  await expect(page.getByTestId("api-docs-toc")).toBeVisible();
  await expect(
    page.getByTestId("api-docs-toc").getByRole("link", { name: "Errors" }),
  ).toBeVisible();
  const responseExamples = page.locator('[data-testid^="api-docs-response-"]');
  await expect(responseExamples).toHaveCount(10);
  const firstEndpoint = page.locator('[data-testid^="api-docs-endpoint-"]').first();
  await firstEndpoint.locator("summary").click();
  await expect(firstEndpoint.locator("pre").last()).toContainText("provenance");

  await expect(page.getByTestId("api-docs-base-url")).toContainText("/api/v1");
  await expect(page.getByTestId("api-docs-auth")).toContainText("None");
  await expect(page.getByTestId("api-docs-rate-limits")).toContainText("600 requests per minute");
  await expect(page.getByTestId("api-docs-pagination")).toContainText("opaque");
  await expect(page.getByTestId("api-docs-freshness")).toContainText("never call upstream");
  await expect(page.getByTestId("api-docs-errors")).toContainText("RATE_LIMITED");
  await expect(page.getByTestId("api-docs-deprecation")).toContainText("/api/v2");
  await expect(page.getByTestId("api-docs-spec-download")).toContainText("v1.yaml");
  await expect(page.getByTestId("api-docs-guides")).toContainText("cves.md");

  for (const slug of EXPECTED_ROWS) {
    await expect(page.getByTestId(`api-docs-row-${slug}`)).toBeVisible();
    const example = page.getByTestId(`api-docs-example-${slug}`);
    await expect(example, `missing example for ${slug}`).toBeVisible();
    await expect(example).toContainText('curl "http');
    await expect(example).toContainText("/api/v1/");
  }

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow at 1280px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/api-docs-1280.png`, fullPage: true });
});

test("api-docs examples use the spec origin and shape-true responses", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/api-docs");

  // Curl examples must never leak the machine's own origin (private IPs,
  // loopback, or Tailscale addresses): they use the spec's example origin.
  const curl = page.getByTestId("api-docs-example-get-api-v1-cves-cveid");
  await expect(curl).toContainText('curl "https://radar.example.org/api/v1/cves/');
  await expect(curl).not.toContainText("127.0.0.1");
  await expect(curl).not.toContainText("localhost");

  // Illustrative responses mirror the live shapes key for key.
  await expect(page.getByTestId("api-docs-response-get-api-v1-search")).toContainText(
    "cvssPrimary",
  );
  await expect(page.getByTestId("api-docs-response-get-api-v1-status")).toContainText(
    "joinCoverage",
  );
  await expect(page.getByTestId("api-docs-response-get-api-v1-replay-checkpoints")).toContainText(
    "retainedFrom",
  );
  await expect(page.getByTestId("api-docs-response-get-api-v1-radar")).toContainText("eventId");
});

test("api-docs stays readable at 360px", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 900 });
  await page.goto("/api-docs");

  await expect(page.getByTestId("api-docs-root")).toBeVisible();
  await expect(page.getByTestId("api-docs-endpoints")).toBeVisible();
  for (const slug of EXPECTED_ROWS) {
    await expect(page.getByTestId(`api-docs-example-${slug}`)).toContainText("curl");
  }

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow, "horizontal overflow at 360px").toBeLessThanOrEqual(1);

  await page.screenshot({ path: `${EVIDENCE_DIR}/api-docs-360.png`, fullPage: true });
});

test("masthead API link navigates from the methodology page", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/methodology", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("methodology-masthead")).toBeVisible({ timeout: 30000 });
  await expect(
    page.getByTestId("methodology-masthead").getByRole("link", { name: "API" }),
  ).toBeVisible({
    timeout: 30000,
  });

  await page.getByTestId("methodology-masthead").getByRole("link", { name: "API" }).click();
  await expect(page).toHaveURL(/\/api-docs$/);
  await expect(page.getByTestId("api-docs-root")).toBeVisible();
});
