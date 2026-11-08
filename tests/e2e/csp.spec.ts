import { expect, test } from "@playwright/test";

// Content-Security-Policy contract. A policy that silently breaks the client is
// worse than none: charts are React-rendered SVG and the theme is client state,
// so the assertions below fail if a script was blocked.
test("pages ship a nonce-scoped CSP and nothing is blocked", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });

  const violations: string[] = [];
  page.on("console", (message) => {
    const text = message.text();
    if (/Content Security Policy|Refused to/i.test(text)) violations.push(text.slice(0, 200));
  });
  page.on("pageerror", (error) => violations.push(`pageerror: ${error.message.slice(0, 200)}`));

  const response = await page.goto("/");
  expect(response).not.toBeNull();
  const policy = response?.headers()["content-security-policy"] ?? "";
  expect(policy).toContain("default-src 'self'");
  expect(policy).toContain("frame-ancestors 'none'");
  expect(policy).toContain("object-src 'none'");

  const nonce = /'nonce-([^']+)'/.exec(policy)?.[1] ?? "";
  expect(nonce).not.toBe("");
  // Production builds are nonce-only; the dev server injects inline HMR script
  // and therefore allows 'unsafe-inline'. Assert the matching contract for each.
  const nonceOnly = !/script-src[^;]*'unsafe-inline'/.test(policy);
  // Read the raw response body: browsers deliberately hide the `nonce` attribute
  // from the DOM after parsing, so `page.content()` cannot see it.
  const html = (await response?.body())?.toString("utf8") ?? "";
  if (nonceOnly) {
    const scriptNonces = new Set(
      [...html.matchAll(/<script[^>]*nonce="([^"]+)"/g)].map((match) => match[1]),
    );
    expect([...scriptNonces]).toEqual([nonce]);
    expect(html).not.toMatch(/<script(?![^>]*nonce=)[^>]*>/);
  } else {
    expect(policy).toContain("'unsafe-eval'");
  }

  // Nothing blocked, and the page still behaves like a client app.
  await expect(page.getByTestId(/^overview-volume-bar-/).first()).toBeVisible();
  await page.getByTestId("theme-toggle").click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", "");
  expect(violations).toEqual([]);
});

test("API responses keep their own strict policy", async ({ request }) => {
  const response = await request.get("/api/v1/health");
  const policy = response.headers()["content-security-policy"] ?? "";
  // Pages get the nonce policy; JSON gets a document-free policy.
  expect(policy).toContain("default-src 'none'");
  expect(policy).not.toContain("nonce-");
});
