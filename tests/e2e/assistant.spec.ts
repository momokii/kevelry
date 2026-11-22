// The assistant desk in a real browser, offline.
//
// The provider is the test-only fake transport (`AI_FAKE_TRANSPORT=1`), so the
// page streams a canned tool call and a canned answer with no socket and no key;
// the tool call itself is real, and runs against the seeded `.e2e` corpus, which
// is why the ledger's row count and the citation chips are asserted against it.
// The disabled state comes from the second dev server, which boots with
// `AI_ENABLED=false` — the same flag an operator would flip.
//
// What this file proves: the empty state offers counted questions, a question
// streams tool activity before any prose, citations appear as links to /explore,
// Stop aborts and keeps what arrived, the disabled desk has no composer, a
// keyboard-only run works, and 390px never overflows. What it does not prove:
// that a real model answers well. No test can prove that.

import { expect, test } from "@playwright/test";

import {
  A11Y_EVIDENCE_DIR,
  auditNoHorizontalOverflow,
  auditReducedMotion,
  auditRoute,
  auditZoomReflow,
  ensureA11yEvidenceDir,
} from "./a11y-audit";
import { resetToBaseline } from "./corpus";

/** The second dev server: the same app with the assistant switched off. */
const DISABLED_ORIGIN = "http://localhost:3211";

/** Screenshots for the change report; never committed. */
const EMPTY_SHOT = "/tmp/assistant-empty-1440.png";
const MIDSTREAM_SHOT = "/tmp/assistant-midstream-1440.png";

const QUESTION = "Which KEV entries were added in the last 30 days?";

test.beforeAll(async ({ request }) => {
  // The ledger's row count and the citation ids are asserted against the seeded
  // corpus, so this file starts from the documented baseline rather than from
  // whatever the previous spec deployed.
  resetToBaseline();
  // Warm the route before any test drives it. On a cold dev server the first
  // POST compiles the handler, and the compile pushes a Fast Refresh to the open
  // page — which remounts the desk and aborts the request it just made. That is
  // a property of `next dev`, not of the desk, so it is paid for once here, with
  // no page open to interrupt.
  await request
    .post("/api/assistant/chat", {
      data: { messages: [{ role: "user", content: "Warm the assistant route." }] },
    })
    .catch(() => undefined);
});

test("the empty desk offers counted questions and an empty ledger", async ({ page }) => {
  await page.goto("/assistant");
  await expect(page.locator("h1")).toHaveText("Ask the corpus");
  await expect(page.locator('[data-testid="assistant-asof"]')).toContainText("corpus as of");

  const suggestion = page.locator('[data-testid="assistant-suggestion-kev-additions"]');
  await expect(suggestion).toBeVisible();
  // The count is the corpus's, and it is printed with its noun, never bare.
  await expect(suggestion.locator(".assistant-suggestion-count")).toHaveText(
    /^\d[\d,]* KEV additions$/,
  );
  // Three questions on this corpus, each with a non-zero count: the baseline has
  // KEV additions, published records and EPSS scores, and no exploit-tagged or
  // due-soon rows, so the latter two must be absent rather than offered at zero.
  await expect(page.locator('[data-testid^="assistant-suggestion-"]')).toHaveCount(3);
  await expect(page.locator('[data-testid="assistant-suggestion-exploit-tagged"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-suggestion-kev-due"]')).toHaveCount(0);
  for (const count of await page.locator(".assistant-suggestion-count").allInnerTexts()) {
    expect(count).not.toMatch(/^0 /);
  }

  await expect(page.locator('[data-testid="assistant-ledger-empty"]')).toBeVisible();
  await expect(page.locator("#assistant-question")).toBeVisible();
  await expect(page.locator('[data-testid="assistant-send"]')).toBeDisabled();
});

test("a question streams tool activity, then text, then server citations", async ({ page }) => {
  await page.goto("/assistant");
  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();

  // Activity in words, before any prose: the reader is told what is running.
  const activity = page.locator('[data-testid="assistant-activity"]');
  await expect(activity).toBeVisible();
  await expect(activity).toContainText("checking the KEV window");
  await expect(activity).toContainText("records");
  await expect(page.locator('[data-testid="assistant-stop"]')).toBeVisible();

  const answer = page.locator('[data-testid="assistant-answer"]');
  await expect(answer).toContainText("canned answer of the test transport");
  await expect(activity).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-stop"]')).toHaveCount(0);

  // Citations come from the server's event, never from the prose.
  const citations = page.locator('[data-testid="assistant-citation"]');
  await expect(citations.first()).toBeVisible();
  await expect(citations.first()).toHaveAttribute("href", /^\/explore\?q=CVE-\d{4}-\d+$/);

  // The ledger is the proof: the call, its arguments, its row count, its ids.
  const entry = page.locator('[data-testid="assistant-ledger-entry"]').first();
  await expect(entry).toContainText("kev_window");
  await expect(entry).toContainText("days=30");
  await expect(entry.locator(".assistant-ledger-rows")).toHaveText(/^\d+ rows$/);
  await expect(entry.locator('a[href^="/explore?q=CVE-"]').first()).toBeVisible();

  // Focus stayed in the composer, and the question was cleared for the next one.
  await expect(page.locator("#assistant-question")).toBeFocused();
  await expect(page.locator("#assistant-question")).toHaveValue("");

  // Nothing is stored: a reload is a new desk, as the composer's note promises.
  await page.reload();
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-empty"]')).toBeVisible();
});

test("Stop aborts the turn and keeps what arrived", async ({ page }) => {
  await page.goto("/assistant");
  await page.locator("#assistant-question").fill(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-activity"]')).toBeVisible();

  await page.locator('[data-testid="assistant-stop"]').click();
  await expect(page.locator('[data-testid="assistant-stopped"]')).toBeVisible();
  // The composer is usable again and the partial turn stays on screen.
  await expect(page.locator('[data-testid="assistant-send"]')).toBeVisible();
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);
});

test("a keyboard-only run asks, streams and stops without a pointer", async ({ page }) => {
  await page.goto("/assistant");
  for (let step = 0; step < 40; step += 1) {
    const focused = await page.evaluate(() => document.activeElement?.id === "assistant-question");
    if (focused) break;
    await page.keyboard.press("Tab");
  }
  await expect(page.locator("#assistant-question")).toBeFocused();

  await page.keyboard.type(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-activity"]')).toBeVisible();

  // Stop is the very next stop after the composer, and Enter operates it.
  await page.keyboard.press("Tab");
  await expect(page.locator('[data-testid="assistant-stop"]')).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-stopped"]')).toBeVisible();
});

test("a pinned record scopes the request and can be removed", async ({ page }) => {
  await page.goto("/assistant?cve=CVE-2099-0001");
  const context = page.locator('[data-testid="assistant-context"]');
  await expect(context).toContainText("about");
  await expect(context).toContainText("CVE-2099-0001");

  await page.locator("#assistant-question").fill("What is this record?");
  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) =>
        candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST",
    ),
    page.keyboard.press("Enter"),
  ]);
  expect(request.postDataJSON()).toMatchObject({ cveContext: "CVE-2099-0001" });
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );

  await page.locator(".assistant-context-clear").click();
  await expect(page.locator('[data-testid="assistant-context"]')).toHaveCount(0);
});

test("the disabled desk names the variable and has no composer", async ({ page }) => {
  await page.goto(`${DISABLED_ORIGIN}/assistant`);
  const disabled = page.locator('[data-testid="assistant-disabled"]');
  await expect(disabled).toBeVisible();
  await expect(disabled).toContainText("AI_ENABLED");
  await expect(disabled).toContainText("off");
  // No fake chat UI in this state: no field, no send button, no suggestion.
  await expect(page.locator("#assistant-question")).toHaveCount(0);
  await expect(page.locator("textarea")).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-send"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-suggestion-kev-additions"]')).toHaveCount(0);
});

test("390px has no horizontal overflow, with the ledger folded below", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/assistant");
  await auditNoHorizontalOverflow(page, "assistant empty at 390px");

  const ledger = page.locator('[data-testid="assistant-ledger"]');
  await expect(ledger).toBeVisible();
  await expect(ledger.locator("summary")).toBeVisible();
  await expect(page.locator('[data-testid="assistant-ledger-disclosure"]')).not.toHaveAttribute(
    "open",
    "",
  );

  await page.locator("#assistant-question").fill(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  await auditNoHorizontalOverflow(page, "assistant answer at 390px");

  // The chips never break mid-id: each citation is a whole, wrapped link.
  const chip = page.locator('[data-testid="assistant-citation"]').first();
  await expect(chip).toBeVisible();
  const box = await chip.boundingBox();
  expect(box?.width ?? 0).toBeLessThanOrEqual(390);
});

test("accessibility audit, zoom reflow and reduced motion stay clean", async ({ page }) => {
  ensureA11yEvidenceDir();
  await auditRoute(page, { route: "/assistant", name: "assistant", maxLiveRegions: 2 });
  await auditZoomReflow(page, "assistant", `${A11Y_EVIDENCE_DIR}/assistant-zoom.png`);
  await auditReducedMotion(page, "assistant", `${A11Y_EVIDENCE_DIR}/assistant-reduced-motion.png`);
});

test("captures the empty and mid-stream states at 1440x900", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/assistant");
  await expect(page.locator('[data-testid="assistant-empty"]')).toBeVisible();
  await page.screenshot({ path: EMPTY_SHOT });

  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();
  // Mid-stream means: the tool has run (its ledger line is there) and the prose
  // has not started. The fake holds that window open on purpose.
  await expect(page.locator('[data-testid="assistant-activity"]')).toContainText(
    "checking the KEV window",
  );
  await expect(page.locator('[data-testid="assistant-ledger-entry"]').first()).toBeVisible();
  await page.screenshot({ path: MIDSTREAM_SHOT });

  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
});
