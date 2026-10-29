import { expect, test } from "@playwright/test";

// v1 public surface: crawlers, social cards, and the 404 page.
test("robots keeps crawlers off the API and showcase", async ({ request }) => {
  const response = await request.get("/robots.txt");
  expect(response).toBeOK();
  const body = await response.text();
  expect(body).toContain("Disallow: /api/");
  expect(body).toContain("Disallow: /showcase");
});

test("sitemap lists the public pages", async ({ request }) => {
  const response = await request.get("/sitemap.xml");
  expect(response).toBeOK();
  const body = await response.text();
  for (const path of ["/", "/explore", "/priority", "/methodology", "/api-docs"]) {
    expect(body).toContain(path);
  }
  expect(body).not.toContain("/showcase");
});

test("favicon serves from the app icon", async ({ request }) => {
  const response = await request.get("/favicon.ico");
  expect(response).toBeOK();
});

test("unknown route renders the branded 404", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/no-such-page-here");
  await expect(page.getByTestId("not-found-root")).toBeVisible();
  await expect(page.getByTestId("not-found-root")).toContainText("Nothing retained here");
  await page.getByRole("link", { name: "Back to overview" }).click();
  // The overview route cold-compiles on a fresh dev server; allow it time.
  await expect(page).toHaveURL("/", { timeout: 20000 });
  await expect(page.getByTestId("overview-root")).toBeVisible({ timeout: 20000 });
});

test("pages carry framing and referrer hardening", async ({ request }) => {
  const response = await request.get("/");
  expect(response).toBeOK();
  expect(response.headers()["x-frame-options"]).toBe("DENY");
  expect(response.headers()["referrer-policy"]).toBe("no-referrer");
  expect(response.headers()["x-content-type-options"]).toBe("nosniff");
  expect(response.headers()["permissions-policy"]).toContain("camera=()");
});

test("showcase asks crawlers not to index", async ({ page }) => {
  await page.goto("/showcase");
  const robots = page.locator('meta[name="robots"]');
  await expect(robots).toHaveAttribute("content", /noindex/);
});
