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

import { readFile } from "node:fs/promises";

import { expect, test, type Page, type Request } from "@playwright/test";

import {
  A11Y_EVIDENCE_DIR,
  auditNoHorizontalOverflow,
  auditReducedMotion,
  auditRoute,
  auditZoomReflow,
  ensureA11yEvidenceDir,
} from "./a11y-audit";
import { resetToBaseline } from "./corpus";
import {
  AI_FAKE_ABORT_MARKER,
  AI_FAKE_HEADING_MARKER,
  AI_FAKE_TABLE_MARKER,
  AI_FAKE_UNSUPPORTED_ID,
} from "../../app/api/assistant/_lib/fake-transport";

/** The second dev server: the same app with the assistant switched off. */
const DISABLED_ORIGIN = "http://localhost:3211";

/** Screenshots for the change report; never committed. */
const EMPTY_SHOT = "/tmp/assistant-empty-1440.png";
const MIDSTREAM_SHOT = "/tmp/assistant-midstream-1440.png";
const RAIL_COLLAPSED_SHOT = "/tmp/assistant-rail-collapsed-1440.png";
const RAIL_EXPANDED_SHOT = "/tmp/assistant-rail-expanded-1440.png";
const PROGRESS_SHOT = "/tmp/progress-streaming.png";
const RETAINED_SHOT = "/tmp/assistant-retained-1440.png";
const REMOVED_SHOT = "/tmp/assistant-screenshot-removed-1440.png";
const ATTACH_GUIDE_SHOT = "/tmp/attach-guide.png";
const ERROR_RETRY_SHOT = "/tmp/error-retry.png";
const PHONE_ATTACH_SHOT = "/tmp/390-attach.png";

const QUESTION = "Which KEV entries were added in the last 30 days?";

/**
 * Opens the desk and lets hydration finish.
 *
 * Every interaction below is a React handler. On a cold dev server the
 * server-rendered markup can be painted (and clicked) before the client bundle
 * attaches those handlers, which looks exactly like a broken feature. Waiting
 * for the network to go quiet is the cheapest reliable signal in this suite.
 */
async function gotoDesk(page: Page): Promise<void> {
  await page.goto("/assistant");
  await page.waitForLoadState("networkidle");
}

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
  // Its own rate-limit identity: the warm-up must not spend the page's 10/min
  // budget, which the journeys below rely on.
  await request
    .post("/api/assistant/chat", {
      headers: { "x-forwarded-for": "203.0.113.77" },
      data: { messages: [{ role: "user", content: "Warm the assistant route." }] },
    })
    .catch(() => undefined);
});

test("the empty desk offers counted questions and an empty ledger", async ({ page }) => {
  await gotoDesk(page);
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

  // The rail explains itself in one sentence pair, not a paragraph.
  await expect(page.locator('[data-testid="assistant-ledger-legend"]')).toContainText(
    "Each line is one server-side lookup",
  );
  // And the page states its contract once, closed, under the lede.
  const how = page.locator('[data-testid="assistant-how"]');
  await expect(how).toBeVisible();
  await expect(how).not.toHaveAttribute("open", "");
  await how.locator("summary").click();
  await expect(how).toContainText("Nothing you type is stored");
});

test("a question streams tool activity, then text, then server citations", async ({ page }) => {
  await gotoDesk(page);
  // Hydration is what attaches the click handler; on a cold dev server the
  // first click can otherwise land on server-rendered markup and do nothing.
  await page.waitForLoadState("networkidle");
  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();

  // Activity in words, before any prose: the reader is told what is running.
  const working = page.locator('[data-testid="assistant-working"]');
  await expect(working).toBeVisible();
  await expect(working.locator('[data-testid="assistant-working-stage"]')).toContainText(
    "checking the KEV window",
  );
  await expect(working).toContainText("records");
  await expect(page.locator('[data-testid="assistant-stop"]')).toBeVisible();

  const answer = page.locator('[data-testid="assistant-answer"]');
  await expect(answer).toContainText("canned answer of the test transport");
  await expect(working).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-stop"]')).toHaveCount(0);

  // Citations come from the server's event, never from the prose. The turn's
  // union is one line until it is opened: the rail is already per call.
  const citedLabel = page.locator('[data-testid="assistant-citations-label"]');
  await expect(citedLabel).toHaveText(/^\d+ records? cited$/);

  // The ledger is the proof: the call, its arguments, its row count, its ids.
  const entry = page.locator('[data-testid="assistant-ledger-entry"]').first();
  await expect(entry).toContainText("kev_window");
  await expect(entry).toContainText("days=30");
  await expect(entry.locator(".assistant-ledger-rows")).toHaveText(/^\d+ rows$/);
  await expect(entry.locator('a[href^="/explore?q=CVE-"]').first()).toBeVisible();

  // Focus stayed in the composer, and the question was cleared for the next one.
  // Read before the disclosure is opened: opening one takes focus, by design.
  await expect(page.locator("#assistant-question")).toBeFocused();
  await expect(page.locator("#assistant-question")).toHaveValue("");

  // Opened, the one line is the chips the answer may cite, from the event.
  await page.locator('[data-testid="assistant-citations"] summary').click();
  const citations = page.locator('[data-testid="assistant-citation"]');
  await expect(citations.first()).toBeVisible();
  await expect(citations.first()).toHaveAttribute("href", /^\/explore\?q=CVE-\d{4}-\d+$/);

  // Nothing is stored: a reload is a new desk, as the composer's note promises.
  await page.reload();
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-empty"]')).toBeVisible();
});

test("Stop aborts the turn and keeps what arrived", async ({ page }) => {
  await gotoDesk(page);
  await page.locator("#assistant-question").fill(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-working"]')).toBeVisible();

  await page.locator('[data-testid="assistant-stop"]').click();
  await expect(page.locator('[data-testid="assistant-stopped"]')).toBeVisible();
  // The composer is usable again and the partial turn stays on screen.
  await expect(page.locator('[data-testid="assistant-send"]')).toBeVisible();
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);
});

test("the working state shows a swept bar, a stage and an elapsed counter", async ({ page }) => {
  // Its own rate-limit identity: this file spends the ten turns a client gets
  // per minute across the journeys above.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.92" });
  await page.setViewportSize({ width: 1440, height: 900 });
  await gotoDesk(page);
  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();

  const working = page.locator('[data-testid="assistant-working"]');
  await expect(working).toBeVisible();
  // One polite region, in the composer foot, where Stop already lives.
  await expect(working).toHaveAttribute("role", "status");
  await expect(working).toHaveAttribute("aria-live", "polite");
  await expect(page.locator('[data-testid="assistant-working-stage"]')).toContainText(
    "checking the KEV window",
  );
  await expect(page.locator('[data-testid="assistant-stop"]')).toHaveText("Stop");

  // The bar animates: the running class is on the track, the sweep is a real
  // keyframes name on the segment inside it.
  const bar = page.locator('[data-testid="assistant-progress"]');
  await expect(bar).toHaveClass(/is-running/);
  expect(await bar.locator("span").evaluate((el) => getComputedStyle(el).animationName)).not.toBe(
    "none",
  );

  // The counter ticks four times a second, so two samples 400ms apart differ.
  const counter = page.locator('[data-testid="assistant-working-elapsed"]');
  await expect(counter).toHaveAttribute("aria-hidden", "true");
  const first = await counter.innerText();
  expect(first).toMatch(/^(\d+\.\d|\d+)s$/);
  // Photographed mid-stream, counter visible, before the prose replaces it.
  await page.screenshot({ path: PROGRESS_SHOT });
  await page.waitForTimeout(400);
  expect(await counter.innerText()).not.toBe(first);

  // The prose is the movement once it arrives: the bar and the row go.
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  await expect(working).toHaveCount(0);
  await expect(bar).toHaveCount(0);
});

test("reduced motion holds the bar filled and lets the counter carry liveness", async ({
  page,
}) => {
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.93" });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await gotoDesk(page);
  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();

  const bar = page.locator('[data-testid="assistant-progress"]');
  await expect(bar).toBeVisible();
  const segment = bar.locator("span");
  // The global reduced-motion rule collapses every duration to zero, so the
  // sweep would freeze off-screen; the explicit rule leaves a filled bar instead.
  expect(await segment.evaluate((el) => getComputedStyle(el).animationDuration)).toBe("0s");
  expect(await segment.evaluate((el) => getComputedStyle(el).width)).toBe(
    await bar.evaluate((el) => getComputedStyle(el).width),
  );

  // Liveness is the counter's job now, and it still moves.
  const counter = page.locator('[data-testid="assistant-working-elapsed"]');
  const first = await counter.innerText();
  await page.waitForTimeout(400);
  expect(await counter.innerText()).not.toBe(first);
  await page.emulateMedia({ reducedMotion: "no-preference" });
});

test("a keyboard-only run asks, streams and stops without a pointer", async ({ page }) => {
  await gotoDesk(page);
  for (let step = 0; step < 40; step += 1) {
    const focused = await page.evaluate(() => document.activeElement?.id === "assistant-question");
    if (focused) break;
    await page.keyboard.press("Tab");
  }
  await expect(page.locator("#assistant-question")).toBeFocused();

  await page.keyboard.type(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-working"]')).toBeVisible();

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
  await gotoDesk(page);
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

  // The chips never break mid-id: each citation is a whole, wrapped link. The
  // block is folded, so it is opened first — the summary is the whole line.
  await page.locator('[data-testid="assistant-citations"] summary').click();
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

test("a formatted answer renders a real table and the page still audits clean", async ({
  page,
}) => {
  ensureA11yEvidenceDir();
  // This journey spends its own rate-limit identity. The desk allows ten turns a
  // minute per client, this file already spends them, and the identity is the
  // one the route itself uses — the same technique the warm-up above relies on.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.88" });

  await auditRoute(page, {
    route: "/assistant",
    name: "assistant answer table",
    maxLiveRegions: 2,
    // The state under audit is an answer, so it is produced before anything is
    // measured: the renderer's output is what the audit has to see.
    beforeAudit: async (current) => {
      await current.waitForLoadState("networkidle");
      await current
        .locator("#assistant-question")
        .fill(`Which KEV entries were added? Answer ${AI_FAKE_TABLE_MARKER}.`);
      await current.keyboard.press("Enter");

      const answer = current.locator('[data-testid="assistant-answer"]');
      await expect(answer).toContainText("canned answer of the test transport");

      // The model wrote pipes; the page shows a table, not a paragraph of pipes.
      const table = answer.locator("table");
      await expect(table).toBeVisible();
      await expect(answer).not.toContainText("| --- |");
      await expect(table.locator("thead th")).toHaveCount(3);
      await expect(table.locator("tbody tr")).toHaveCount(2);
      await expect(table.locator("thead th").first()).toHaveAttribute("scope", "col");

      // The wrapper is the app's scroll container and is keyboard reachable, so
      // a wide table can be read without a pointer.
      const wrapper = current.locator('[data-testid="assistant-table"]');
      await expect(wrapper).toHaveClass(/table-wrap/);
      await expect(wrapper).toHaveAttribute("tabindex", "0");
      expect(await wrapper.evaluate((el) => getComputedStyle(el).overflowX)).toBe("auto");

      // A phone scrolls the table inside its wrapper, never the page.
      await current.setViewportSize({ width: 390, height: 844 });
      await auditNoHorizontalOverflow(current, "assistant answer table at 390px");
      expect(await wrapper.evaluate((el) => getComputedStyle(el).overflowX)).toBe("auto");
      await current.setViewportSize({ width: 1280, height: 900 });
    },
  });

  // Still on screen after the audit: the table was not a transient render.
  await expect(page.locator('[data-testid="assistant-answer"] table')).toBeVisible();
});

test("an answer's first heading never skips a level under the page h1", async ({ page }) => {
  ensureA11yEvidenceDir();
  // Its own rate-limit identity, for the same reason the table journey has one:
  // this file spends the ten turns a client gets per minute.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.89" });

  await auditRoute(page, {
    route: "/assistant",
    name: "assistant answer heading",
    maxLiveRegions: 2,
    // `auditRoute` checks that no heading jumps more than one level. It needs an
    // answer that actually carries a heading, because that is where the skip
    // was: the renderer clamps a model `###` to an `h3`, and the transcript
    // region had no `h2` for it to sit under.
    beforeAudit: async (current) => {
      await current.waitForLoadState("networkidle");
      await current
        .locator("#assistant-question")
        .fill(`Which KEV entries were added? Answer ${AI_FAKE_HEADING_MARKER}.`);
      await current.keyboard.press("Enter");

      const answer = current.locator('[data-testid="assistant-answer"]');
      await expect(answer).toContainText("canned answer of the test transport");
      await expect(answer.locator("h3")).toHaveText("Canned answer");
    },
  });

  // The sequence the audit just walked, stated plainly: the page h1, the
  // transcript's own h2, then the answer's h3. Before the fix it read 1 → 3.
  const levels = await page.evaluate(() =>
    Array.from(document.querySelectorAll("h1, h2, h3, h4")).map((el) =>
      Number(el.tagName.slice(1)),
    ),
  );
  expect(levels.slice(0, 3)).toEqual([1, 2, 3]);
  await expect(page.getByRole("heading", { level: 2, name: "Answer", exact: true })).toHaveCount(1);
});

test("captures the empty and mid-stream states at 1440x900", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await gotoDesk(page);
  await expect(page.locator('[data-testid="assistant-empty"]')).toBeVisible();
  await page.screenshot({ path: EMPTY_SHOT });

  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();
  // Mid-stream means: the tool has run (its ledger line is there) and the prose
  // has not started. The fake holds that window open on purpose.
  await expect(page.locator('[data-testid="assistant-working-stage"]')).toContainText(
    "checking the KEV window",
  );
  await expect(page.locator('[data-testid="assistant-ledger-entry"]').first()).toBeVisible();
  await page.screenshot({ path: MIDSTREAM_SHOT });

  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
});

/**
 * The dense rail, photographed both ways.
 *
 * Four questions give four calls — one more than the rail shows — so the
 * collapsed shot is the state a reader meets and the expanded shot is what the
 * control reveals. Its own rate-limit identity: this test asks four times, and
 * the page's 10/minute budget is spent by the journeys above.
 */
test("captures the rail collapsed and expanded at 1440x900", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.91" });
  await gotoDesk(page);
  for (let index = 0; index < 4; index += 1) {
    await page.locator("#assistant-question").fill(`${QUESTION} (${String(index + 1)})`);
    await page.keyboard.press("Enter");
    await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(index + 1);
    await expect(page.locator('[data-testid="assistant-answer"]').nth(index)).toContainText(
      "canned answer of the test transport",
    );
  }

  // The rail caps itself: three calls, and one control naming the real total.
  const control = page.locator('[data-testid="assistant-ledger-calls-more"]');
  await expect(control).toHaveText("See all 4 calls");
  await expect(page.locator('[data-testid="assistant-ledger-entry"]')).toHaveCount(3);
  await page.screenshot({ path: RAIL_COLLAPSED_SHOT });

  await control.click();
  await expect(page.locator('[data-testid="assistant-ledger-entry"]')).toHaveCount(4);
  await page.screenshot({ path: RAIL_EXPANDED_SHOT });
});

/**
 * A 240×120 PNG with a header strip and three colour bands: the shape of an
 * advisory panel. The 1×1 fixture below proves the plumbing; this one is what the
 * retained turn is photographed with, because a single pixel says nothing about
 * `object-fit: cover` or about an expanded copy at its natural size.
 */
const ADVISORY_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAPAAAAB4CAIAAABD1OhwAAACB0lEQVR4nO3SwQmEQAAEwY1vI/JxwRiTKfjxfRiASYgLTUEHMAw1ruuUMo3lC6QXA1qpgFYqoJUKaKUCWqmAViqglQpopQJaqYBWKqCVCmilAlqpgFYqoJUKaKUCWqmAViqglQpopQJaqYBWqnHMuaT5O9a0b0vy8zcBDXTqZ6CBTv0MNNCpn4EGOvUz0ECnfgYa6NTPQAOd+hlooFM/Aw106meggU79DDTQqZ+BBjr1M9BAp34GGujUz0ADnfoZaKBTPwMNdOpnoIFO/Qw00KmfgQY69TPQQKd+Bhro1M9AA536GWigUz8DDXTqZ6CBTv0MNNCpn4EGOvUz0ECnfgYa6NTPQAOd+hlooFM/Aw106meggU79DDTQqZ+BBjr1M9BAp34GGujUz0ADnfoZaKBTPwMNdOpnoIFO/Qw00KmfgQY69TPQQKd+Bhro1M9AA536GWigUz8DDXTqZ6CBTv0MNNCpn4EGOvUz0ECnfgYa6NTPQAOd+hlooFM/Aw106meggU79DDTQqZ+BBjr1M9BAp34GGujUz0ADnfoZaKBTPwMNdOpnoIFO/Qw00KmfgQY69TPQQKd+Bhro1M9AA536edz3X8oEtFIBrVRAKxXQSgW0UgGtVEArFdBKBbRSAa1UQCsV0EoFtFIBrVRAKxXQSgW0UgGtVEArFdBKBbRSAa1UQCvVA99gYZLTBgd8AAAAAElFTkSuQmCC",
  "base64",
);

/** A 1x1 PNG: real magic bytes, so the client sniffer and the route agree. */
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64",
);

test("a screenshot is picked, previewed, sent with the question, and removable", async ({
  page,
}) => {
  await gotoDesk(page);
  const input = page.locator('[data-testid="assistant-image-input"]');
  await expect(input).toHaveAttribute("type", "file");
  await expect(input).toHaveAttribute("accept", "image/png,image/jpeg,image/webp");
  // The file input has a real label, and the note says what the image is for.
  await expect(page.locator(".assistant-image-pick")).toHaveText("Attach a screenshot");
  await expect(page.locator("#assistant-image-note")).toContainText(
    "The image is only used to find CVE ids",
  );
  await expect(page.locator("#assistant-image-note")).toContainText(
    "every id is checked against the dataset before it is used",
  );

  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "advisory.png",
    mimeType: "image/png",
    buffer: PNG_1X1,
  });
  const preview = page.locator('[data-testid="assistant-image-preview"]');
  await expect(preview).toBeVisible();
  await expect(preview).toContainText("advisory.png");
  await expect(preview).toContainText("PNG");
  await expect(page.locator('[data-testid="assistant-image-remove"]')).toHaveAttribute(
    "aria-label",
    "Remove advisory.png",
  );

  await page.locator("#assistant-question").fill(QUESTION);
  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) =>
        candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST",
    ),
    page.keyboard.press("Enter"),
  ]);
  const body = request.postDataJSON() as { image?: { dataUrl: string } };
  expect(body.image?.dataUrl).toMatch(/^data:image\/png;base64,/);
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  // The turn's union is one line: the answer cited what the image named.
  await expect(page.locator('[data-testid="assistant-citations-label"]')).toHaveText(
    /^\d+ records? cited$/,
  );
  await page.locator('[data-testid="assistant-citations"] summary').click();
  await expect(page.locator('[data-testid="assistant-citation"]').first()).toBeVisible();
  // The composer's intake is clean again, and the image is held instead: the
  // chip above the field names the file and asks whether the next question
  // wants it. (Before retention this assertion meant "the image is gone"; it now
  // means "the intake is empty", which is what the composer holding one image
  // implies.)
  await expect(preview).toHaveCount(0);
  const contextChip = page.locator('[data-testid="assistant-image-context"]');
  await expect(contextChip).toContainText("use screenshot in this question");
  await expect(contextChip).toContainText("advisory.png");
  // The turn that carried it says so, and nothing on the page claims otherwise.
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveText(
    "Attached with this question",
  );
  await expect(page.locator("body")).not.toContainText("No longer in context");

  // An oversized file is refused in plain language, before it is read.
  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "huge.png",
    mimeType: "image/png",
    buffer: Buffer.alloc(1_600_000),
  });
  const fault = page.locator('[data-testid="assistant-image-fault"]');
  await expect(fault).toContainText("The limit is 1.5 MB");

  // A wrong type is named, and Remove clears a valid attachment.
  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "advisory.gif",
    mimeType: "image/gif",
    buffer: Buffer.from("GIF89a", "utf8"),
  });
  await expect(fault).toContainText("Only PNG, JPEG and WebP");
  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "advisory.png",
    mimeType: "image/png",
    buffer: PNG_1X1,
  });
  await expect(preview).toBeVisible();
  await page.locator('[data-testid="assistant-image-remove"]').click();
  await expect(preview).toHaveCount(0);
  await expect(input).toHaveCount(1);
  // Removing it deletes the payload: the chip goes, one sentence says what that
  // meant, and the turn that was already sent keeps its own record and label.
  await expect(contextChip).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-image-removed"]')).toHaveText(
    "Screenshot removed — it will not be sent again.",
  );
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveText(
    "Attached with this question",
  );
});

/**
 * AC7 — the user's own journey, and the four wire assertions in one place.
 *
 * Attach, ask about it, ask something else, point back at it, remove it, then
 * remove it *mid-stream* — which is the reported repro. The claim under test is
 * narrow and checkable: the payload rides on the questions that asked for it,
 * a turn's label never flips when the composer changes, and `×` ends the picture
 * for good. Byte counts are read off the bodies that actually went out.
 */
test("the screenshot is sent only when the question asks for it", async ({ page }) => {
  // Its own rate-limit identity: this journey sends five turns.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.96" });
  await gotoDesk(page);
  const chatPost = (candidate: Request): boolean =>
    candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST";
  const chatBodies: Array<Record<string, unknown>> = [];
  page.on("request", (candidate) => {
    if (chatPost(candidate)) chatBodies.push(candidate.postDataJSON() as Record<string, unknown>);
  });
  /** The payload, in UTF-8 bytes of the data URL the route received. */
  const imageBytes = (body: Record<string, unknown> | undefined): number => {
    const image = body?.image as { dataUrl?: string } | undefined;
    return image?.dataUrl === undefined ? 0 : Buffer.byteLength(image.dataUrl, "utf8");
  };
  const ask = async (question: string): Promise<Request> => {
    await page.locator("#assistant-question").fill(question);
    const [request] = await Promise.all([
      page.waitForRequest(chatPost),
      page.keyboard.press("Enter"),
    ]);
    await expect(page.locator('[data-testid="assistant-answer"]').last()).toContainText(
      "canned answer of the test transport",
    );
    return request;
  };

  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "advisory.png",
    mimeType: "image/png",
    buffer: ADVISORY_PNG,
  });
  await expect(page.locator('[data-testid="assistant-image-preview"]')).toBeVisible();
  // Staged only: nothing is in context until a turn has carried it.
  await expect(page.locator('[data-testid="assistant-image-context"]')).toHaveCount(0);

  // AC1 — the question the picture was attached for carries it, once.
  const first = await ask("Which CVE ids are in this screenshot?");
  const firstBody = first.postDataJSON() as { image?: { dataUrl: string } };
  expect(Object.hasOwn(firstBody, "image")).toBe(true);
  expect(firstBody.image?.dataUrl).toMatch(/^data:image\/png;base64,/);
  const sentBytes = Buffer.byteLength(firstBody.image?.dataUrl ?? "", "utf8");
  expect(sentBytes).toBe(790);

  // The thumbnail is part of the question block, and the note is the record of
  // the send — not a comment on what the composer is holding now.
  const firstTurn = page.locator('[data-testid="assistant-turn"]').first();
  const shot = firstTurn.locator('[data-testid="assistant-shot"]');
  await expect(shot).toBeVisible();
  await expect(shot.locator(".assistant-shot-summary img")).toHaveAttribute(
    "alt",
    "Attached screenshot",
  );
  await expect(shot.locator("summary")).toContainText("advisory.png");
  await expect(shot.locator("summary")).toContainText("PNG");
  await expect(shot.locator('[data-testid="assistant-shot-note"]')).toHaveText(
    "Attached with this question",
  );
  await expect(firstTurn.locator(".assistant-question")).toBeVisible();
  // The picture is the turn's record, not the payload: nothing on screen carries
  // the full-size data URL as text.
  await expect(shot.locator("summary")).not.toContainText("base64");

  // The expand affordance is keyboard operable and opens in place.
  await shot.locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(shot.locator('[data-testid="assistant-shot-details"]')).toHaveAttribute("open", "");
  await expect(shot.locator(".assistant-shot-full-image")).toBeVisible();
  // The state the change report shows: the picture in the turn, the chip above
  // the composer, and nothing duplicated between them.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: RETAINED_SHOT });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.keyboard.press("Enter");
  await expect(shot.locator('[data-testid="assistant-shot-details"]')).not.toHaveAttribute(
    "open",
    "",
  );

  // The chip is the consent: a labelled native checkbox, the file, and `×`.
  const chip = page.locator('[data-testid="assistant-image-context"]');
  await expect(chip).toBeVisible();
  const consent = page.locator('[data-testid="assistant-image-consent"]');
  await expect(chip.locator("label")).toHaveText("use screenshot in this question");
  // After the send it is unticked again: the next question decides on its words.
  await expect(consent).not.toBeChecked();
  await expect(page.locator('[data-testid="assistant-image-context-remove"]')).toHaveAttribute(
    "aria-label",
    "Remove advisory.png from context",
  );

  // AC2 — a plain policy question sends no payload at all. This is the measured
  // defect: 4.0.5 shipped the same 41,538 bytes here.
  const second = await ask("What is the KEV deadline for federal agencies?");
  const secondBody = second.postDataJSON() as Record<string, unknown>;
  expect(Object.hasOwn(secondBody, "image")).toBe(false);
  expect(imageBytes(secondBody)).toBe(0);
  // The picture is still held — it just was not sent — and the second turn
  // carries no record of it.
  await expect(chip).toBeVisible();
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(2);
  await expect(page.locator('[data-testid="assistant-shot"]')).toHaveCount(1);
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveCount(1);

  // AC3 — a question that points at it sends it again, byte for byte. The
  // checkbox says so before the send, because it is the decision.
  await page.locator("#assistant-question").fill("Explain that screenshot again.");
  await expect(consent).toBeChecked();
  const third = await ask("Explain that screenshot again.");
  const thirdBody = third.postDataJSON() as { image?: { dataUrl: string } };
  expect(Object.hasOwn(thirdBody, "image")).toBe(true);
  expect(thirdBody.image?.dataUrl).toBe(firstBody.image?.dataUrl);
  expect(imageBytes(thirdBody)).toBe(sentBytes);
  await expect(page.locator('[data-testid="assistant-shot"]')).toHaveCount(2);
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveCount(2);

  // AC5 — every turn that sent it says so; the retroactive note is gone.
  for (const note of await page.locator('[data-testid="assistant-shot-note"]').allTextContents()) {
    expect(note).toBe("Attached with this question");
  }
  await expect(page.locator("body")).not.toContainText("No longer in context");

  // AC4 + the reported repro: remove it while a turn is streaming. The request
  // already left with the picture; the label on that in-flight turn must not
  // flip when the composer changes underneath it.
  await page.locator("#assistant-question").fill("Explain that screenshot again.");
  await expect(consent).toBeChecked();
  const [fourth] = await Promise.all([page.waitForRequest(chatPost), page.keyboard.press("Enter")]);
  await expect(page.locator('[data-testid="assistant-working"]')).toBeVisible();
  await page.locator('[data-testid="assistant-image-context-remove"]').click();
  await expect(chip).toHaveCount(0);
  // One sentence, above the composer, saying what `×` meant.
  await expect(page.locator('[data-testid="assistant-image-removed"]')).toHaveText(
    "Screenshot removed — it will not be sent again.",
  );
  await expect(page.locator('[data-testid="assistant-image-removed"]')).toHaveCount(1);
  // The in-flight turn carried it, and its label still says so.
  const fourthBody = fourth.postDataJSON() as { image?: { dataUrl: string } };
  expect(Object.hasOwn(fourthBody, "image")).toBe(true);
  expect(fourthBody.image?.dataUrl).toBe(firstBody.image?.dataUrl);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(4);
  const inFlight = page.locator('[data-testid="assistant-turn"]').nth(3);
  await expect(inFlight.locator('[data-testid="assistant-shot-note"]')).toHaveText(
    "Attached with this question",
  );
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveCount(3);
  await page.evaluate(() => {
    document.querySelector('[data-testid="assistant-shot"]')?.scrollIntoView({ block: "center" });
  });
  await page.screenshot({ path: REMOVED_SHOT });

  // AC4 — after `×`, even a question that names the screenshot sends nothing:
  // removal is the reader's decision, and the words are only a guess.
  const fifth = await ask("And what does the screenshot say the severity is?");
  const fifthBody = fifth.postDataJSON() as Record<string, unknown>;
  expect(Object.hasOwn(fifthBody, "image")).toBe(false);
  expect(imageBytes(fifthBody)).toBe(0);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(5);
  // History keeps its three labels; the composer keeps its one sentence.
  await expect(page.locator('[data-testid="assistant-shot-note"]')).toHaveCount(3);
  await expect(page.locator('[data-testid="assistant-image-removed"]')).toHaveCount(1);

  // The bodies, in order, as the four assertions above claim.
  expect(chatBodies.map((body) => imageBytes(body))).toEqual([
    sentBytes,
    0,
    sentBytes,
    sentBytes,
    0,
  ]);
});

test("the retained screenshot is audited open and fits a phone", async ({ page }) => {
  ensureA11yEvidenceDir();
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.97" });
  await auditRoute(page, {
    route: "/assistant",
    name: "assistant retained screenshot",
    maxLiveRegions: 2,
    beforeAudit: async (current) => {
      await current.waitForLoadState("networkidle");
      await current.setInputFiles('[data-testid="assistant-image-input"]', {
        name: "advisory.png",
        mimeType: "image/png",
        buffer: ADVISORY_PNG,
      });
      await current
        .locator("#assistant-question")
        .fill("Which CVE ids does this screenshot carry?");
      await current.keyboard.press("Enter");
      await expect(current.locator('[data-testid="assistant-answer"]')).toContainText(
        "canned answer of the test transport",
      );
      // Expanded: the picture, its name and the context chip are what is audited,
      // not a page that happens to contain them while folded.
      await current.locator('[data-testid="assistant-shot"] summary').click();
      await expect(current.locator('[data-testid="assistant-shot-details"]')).toHaveAttribute(
        "open",
        "",
      );
      await expect(current.locator('[data-testid="assistant-image-context"]')).toBeVisible();
    },
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await auditNoHorizontalOverflow(page, "assistant retained screenshot at 390px");
  const thumb = await page
    .locator('[data-testid="assistant-shot"] .assistant-shot-thumb')
    .boundingBox();
  // A thumbnail, not a hero: the picture sits in the question at a readable size
  // without pushing the composer off a phone screen.
  expect(thumb?.height ?? 0).toBeGreaterThanOrEqual(96);
  expect(thumb?.height ?? 0).toBeLessThanOrEqual(140);
});

test("the attach guide opens from the keyboard and names what works", async ({ page }) => {
  // Its own rate-limit identity, like every other journey that sends a turn.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.94" });
  await gotoDesk(page);
  const guide = page.locator('[data-testid="assistant-image-guide"]');
  const summary = guide.locator("summary");
  await expect(summary).toHaveText("What works");
  await expect(guide).not.toHaveAttribute("open", "");

  // Keyboard alone: the attach control is the stop before it, and Enter opens a
  // native details without a line of JavaScript.
  await page.locator('[data-testid="assistant-image-input"]').focus();
  await page.keyboard.press("Tab");
  await expect(summary).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(guide).toHaveAttribute("open", "");

  // At least three sources that work and two that do not, all in reader words.
  const useful = [
    "A vendor advisory page showing a CVE id",
    "An NVD or CVE record page",
    "A scanner report or ticket listing CVEs",
    "A PDF page screenshot that carries a CVE id",
  ];
  const useless = [
    "A game scoreboard or a photo",
    "A dashboard with no CVE id, vendor or product name",
  ];
  for (const text of [...useful, ...useless]) await expect(guide).toContainText(text);
  // The pipeline in one sentence: ids are extracted, then checked.
  await expect(guide).toContainText("Each id is then checked against this dataset");
  await expect(guide).toContainText("reported as not here");

  // Space closes it, still without a pointer.
  await page.keyboard.press("Space");
  await expect(guide).not.toHaveAttribute("open", "");
});

test("the attach guide is audited open and fits a phone", async ({ page }) => {
  ensureA11yEvidenceDir();
  await auditRoute(page, {
    route: "/assistant",
    name: "assistant attach guide",
    maxLiveRegions: 2,
    beforeAudit: async (current) => {
      await current.waitForLoadState("networkidle");
      await current.locator('[data-testid="assistant-image-guide"] > summary').focus();
      await current.keyboard.press("Enter");
      await expect(current.locator('[data-testid="assistant-image-guide"]')).toHaveAttribute(
        "open",
        "",
      );
    },
  });
  // The open panel is what the frame shows: guidance is only useful when read.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.evaluate(() => {
    document
      .querySelector('[data-testid="assistant-image-guide"]')
      ?.scrollIntoView({ block: "center" });
  });
  await page.screenshot({ path: ATTACH_GUIDE_SHOT });

  // A phone wraps the lists instead of scrolling the page sideways.
  await page.setViewportSize({ width: 390, height: 844 });
  await auditNoHorizontalOverflow(page, "assistant attach guide at 390px");
  await expect(page.locator('[data-testid="assistant-image-guide"]')).toHaveAttribute("open", "");
  const box = await page.locator('[data-testid="assistant-image-guide"] summary').boundingBox();
  expect(box?.height ?? 0).toBeGreaterThanOrEqual(44);
});

test("the compare disclosure validates two ids and sends one comparison question", async ({
  page,
}) => {
  await gotoDesk(page);
  await page.locator('[data-testid="assistant-compare"] summary').click();
  await expect(page.locator('label[for="assistant-compare-a"]')).toHaveText("First record");

  await page.locator('[data-testid="assistant-compare-a"]').fill("not-an-id");
  await page.locator('[data-testid="assistant-compare-b"]').fill("CVE-2099-0002");
  await page.locator('[data-testid="assistant-compare-send"]').click();
  await expect(page.locator("#assistant-compare-a-error")).toHaveText(
    "Use the form CVE-YYYY-NNNN.",
  );
  await expect(page.locator('[data-testid="assistant-compare-a"]')).toHaveAttribute(
    "aria-invalid",
    "true",
  );

  // The same record twice is refused on the second field.
  await page.locator('[data-testid="assistant-compare-a"]').fill("cve-2099-0001");
  await page.locator('[data-testid="assistant-compare-b"]').fill("CVE-2099-0001");
  await page.locator('[data-testid="assistant-compare-send"]').click();
  await expect(page.locator("#assistant-compare-b-error")).toHaveText(
    "Pick a second record — this is the first one.",
  );

  await page.locator('[data-testid="assistant-compare-b"]').fill("CVE-2099-0002");
  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) =>
        candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST",
    ),
    page.locator('[data-testid="assistant-compare-send"]').click(),
  ]);
  const body = request.postDataJSON() as { messages: Array<{ content: string }> };
  const question = body.messages[body.messages.length - 1]?.content ?? "";
  expect(question).toContain("Compare CVE-2099-0001 and CVE-2099-0002 field by field.");
  expect(question).toContain("KEV membership and catalog due date");
  expect(question).toContain("say that it is missing from the dataset");
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
});

test("an unsupported id in the answer is flagged and never becomes a citation", async ({
  page,
}) => {
  await gotoDesk(page);
  // The fake transport repeats this id in its prose because the question named
  // it; the kev_window tool never returns it. That is the model failure the
  // server's classifier is for — driven by a question, not by a special build.
  await page
    .locator("#assistant-question")
    .fill(`Which KEV entries are new? For reference: ${AI_FAKE_UNSUPPORTED_ID}.`);
  await page.keyboard.press("Enter");

  const warning = page.locator('[data-testid="assistant-unverified"]');
  await expect(warning).toBeVisible();
  await expect(warning).toContainText("1 record id in this answer was not found in the dataset");
  await expect(warning).toContainText(AI_FAKE_UNSUPPORTED_ID);
  await expect(warning).toHaveAttribute("data-count", "1");

  // The supported records are still chipped; the unsupported id is not, and it
  // never gets a link that would imply the dataset holds it.
  await page.locator('[data-testid="assistant-citations"] summary').click();
  const citations = page.locator('[data-testid="assistant-citation"]');
  await expect(citations.first()).toBeVisible();
  await expect(page.locator(`a[href="/explore?q=${AI_FAKE_UNSUPPORTED_ID}"]`)).toHaveCount(0);
  expect(await citations.allInnerTexts()).not.toContain(AI_FAKE_UNSUPPORTED_ID);

  // The exported brief carries the same doubt, under its own heading.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator('[data-testid="assistant-brief"]').click(),
  ]);
  const path = await download.path();
  expect(path).not.toBeNull();
  const text = await readFile(path as string, "utf8");
  expect(text).toContain("## Unverified ids");
  expect(text).toContain(`- \`${AI_FAKE_UNSUPPORTED_ID}\``);
});

test("a completed answer exports a brief and offers a ledger-derived follow-up", async ({
  page,
}) => {
  await gotoDesk(page);
  await page.locator('[data-testid="assistant-suggestion-kev-additions"]').click();
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );

  // The brief: question, answer, absolute citations, evidence, model and footer.
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.locator('[data-testid="assistant-brief"]').click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^kevelry-brief-\d{4}-\d{2}-\d{2}\.md$/);
  const path = await download.path();
  expect(path).not.toBeNull();
  const text = await readFile(path as string, "utf8");

  expect(text.startsWith(`# ${QUESTION}`)).toBe(true);
  expect(text).toContain("canned answer of the test transport");
  expect(text).toContain("## Citations");
  expect(text).toMatch(/\]\(http:\/\/localhost:3210\/explore\?q=CVE-\d{4}-\d+\)/);
  expect(text).toContain("| kev_window | days=30 |");
  expect(text).toContain("model `deepseek-v4.1-flash`");
  expect(text).toContain(
    "The prose above is model-written and grounded only in the records listed in this brief.",
  );
  expect(text).toContain("Every figure comes from the dataset");

  // The follow-up: its id comes from the ledger, and it asks its question verbatim.
  const chip = page.locator('[data-testid="assistant-followup-kev"]').first();
  await expect(chip).toBeVisible();
  const question = (await chip.innerText()).trim();
  expect(question).toMatch(/^When is CVE-\d{4}-\d+ due\?$/);
  const ledgerIds = await page
    .locator('[data-testid="assistant-ledger-entry"] a[href^="/explore?q=CVE-"]')
    .allInnerTexts();
  expect(ledgerIds).toContain(question.replace(/^When is /, "").replace(/ due\?$/, ""));

  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) =>
        candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST",
    ),
    chip.click(),
  ]);
  const body = request.postDataJSON() as { messages: Array<{ content: string }> };
  expect(body.messages[body.messages.length - 1]?.content).toBe(question);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(2);
});

test("the priority and graph entry points pin the record in the desk", async ({ page }) => {
  await page.goto("/priority");
  const ask = page.locator('[data-testid="priority-row-ask"]').first();
  await expect(ask).toBeVisible();
  await expect(ask).toHaveText("Ask about this record");
  const priorityHref = await ask.getAttribute("href");
  expect(priorityHref).toMatch(/^\/assistant\?cve=CVE-\d{4}-\d+$/);
  const priorityId = new URL(`http://localhost${priorityHref ?? ""}`).searchParams.get("cve");

  await ask.click();
  await expect(page).toHaveURL(new RegExp(`/assistant\\?cve=${priorityId ?? ""}$`));
  const context = page.locator('[data-testid="assistant-context"]');
  await expect(context).toContainText(priorityId ?? "");
  const [request] = await Promise.all([
    page.waitForRequest(
      (candidate) =>
        candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST",
    ),
    page
      .locator("#assistant-question")
      .fill("What is this record?")
      .then(() => page.keyboard.press("Enter")),
  ]);
  expect((request.postDataJSON() as { cveContext?: string }).cveContext).toBe(priorityId);

  // The graph drill-down offers the same action on every listed record.
  await page.goto("/graph");
  await expect(
    page.locator('[data-testid="graph-hubs"], [data-testid="graph-empty"]').first(),
  ).toBeVisible();
  const hub = (
    await page.locator('[data-testid="graph-hubs"] a.graph-hub-id').first().innerText()
  ).trim();
  await page.goto(`/graph?focus=${encodeURIComponent(hub)}`);
  // The centered record is the drill-down: every action on it is on this page.
  const graphAsk = page.locator('[data-testid="graph-ask"]');
  await expect(graphAsk).toBeVisible();
  await expect(graphAsk).toHaveText("Ask about this record");
  const graphHref = await graphAsk.getAttribute("href");
  expect(graphHref).toMatch(/^\/assistant\?cve=CVE-\d{4}-\d+$/);

  await graphAsk.click();
  const graphId = new URL(`http://localhost${graphHref ?? ""}`).searchParams.get("cve");
  await expect(page).toHaveURL(new RegExp(`/assistant\\?cve=${graphId ?? ""}$`));
  await expect(page.locator('[data-testid="assistant-context"]')).toContainText(graphId ?? "");
});

/**
 * The four failures a reader actually meets, in the browser.
 *
 * Everything here is one POST and one transcript: a provider that dies
 * mid-answer, Enter pressed while a turn is streaming, a reload mid-stream, and
 * the widest control the desk owns on the narrowest screen. Each journey asserts
 * behaviour — what is on screen, how many requests went out — never the shape of
 * the code behind it.
 */

test("a stream that dies mid-answer is named, marked incomplete and retried in place", async ({
  page,
}) => {
  // Its own rate-limit identity: this journey sends two attempts for one question.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.101" });
  await gotoDesk(page);

  const posts: Request[] = [];
  page.on("request", (candidate) => {
    if (candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST") {
      posts.push(candidate);
    }
  });

  const question = `${QUESTION} ${AI_FAKE_ABORT_MARKER}.`;
  await page.locator("#assistant-question").fill(question);
  await page.keyboard.press("Enter");

  // The inline fault, in the app's voice: a sentence saying what happened, with
  // the code as metadata beside it rather than as the explanation.
  const fault = page.locator('[data-testid="assistant-fault"]');
  await expect(fault).toBeVisible();
  await expect(fault).toHaveAttribute("role", "alert");
  await expect(fault.locator(".assistant-fault-headline")).toHaveText(
    "The provider failed before the answer finished.",
  );
  await expect(fault.locator(".assistant-fault-next")).toContainText("Ask again");
  await expect(fault.locator(".assistant-fault-meta")).toContainText("AI_UPSTREAM_ERROR");

  // What arrived is still on screen — preserved, not discarded — and it is
  // marked as a partial answer rather than passing for a finished one.
  const turn = page.locator('[data-testid="assistant-turn"]').first();
  await expect(turn.locator('[data-testid="assistant-answer"]')).toContainText(
    "This is the canned answer of the test transport",
  );
  await expect(turn.locator('[data-testid="assistant-incomplete"]')).toHaveText(
    "Incomplete: the answer stopped before it finished. What is above is what arrived.",
  );
  // A half-answer is not exported and offers no follow-up built on it.
  await expect(page.locator('[data-testid="assistant-brief"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-followups"]')).toHaveCount(0);
  await page.evaluate(() => {
    document.querySelector('[data-testid="assistant-fault"]')?.scrollIntoView({ block: "center" });
  });
  await page.screenshot({ path: ERROR_RETRY_SHOT });

  // The retry re-sends the same question and the second attempt finishes.
  const retry = page.getByRole("button", { name: "Ask again" });
  await expect(retry).toBeVisible();
  await retry.click();
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "A live deployment never reaches this text.",
  );
  await expect(page.locator('[data-testid="assistant-incomplete"]')).toHaveCount(0);
  await expect(fault).toHaveCount(0);

  // No duplicate turn: one question is one turn, whichever attempt finished it.
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);
  expect(posts).toHaveLength(2);
  const bodies = posts.map(
    (post) => post.postDataJSON() as { messages: Array<{ role: string; content: string }> },
  );
  const asked = bodies.map((body) => body.messages[body.messages.length - 1]?.content);
  expect(asked[0]).toBe(question);
  expect(asked[1]).toBe(question);
  // And the retry did not replay the dead half-answer as conversation history.
  expect(bodies[1]?.messages.filter((message) => message.role === "assistant")).toHaveLength(0);
});

test("Enter during a stream sends nothing, and Stop is the only action", async ({ page }) => {
  // Its own rate-limit identity, like every journey that spends a turn.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.102" });
  await gotoDesk(page);

  let posts = 0;
  page.on("request", (candidate) => {
    if (candidate.url().includes("/api/assistant/chat") && candidate.method() === "POST") {
      posts += 1;
    }
  });

  await page.locator("#assistant-question").fill(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-working"]')).toBeVisible();

  // While a turn streams, the composer's only action is Stop: the send button is
  // gone, the attach control is disabled, and the field is read-only.
  await expect(page.locator('[data-testid="assistant-send"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-stop"]')).toBeVisible();
  await expect(page.locator('[data-testid="assistant-image-input"]')).toBeDisabled();
  await expect(page.locator("#assistant-question")).toHaveAttribute("aria-readonly", "true");

  // Three Enters during the stream: still one request, still one turn.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await page.keyboard.press("Enter");
  }
  expect(posts).toBe(1);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);

  // The turn it did send finishes normally, and the desk is idle again.
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  await expect(page.locator('[data-testid="assistant-send"]')).toBeVisible();
  expect(posts).toBe(1);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);
});

test("a reload mid-stream starts clean, with no fault and no console error", async ({ page }) => {
  // Its own rate-limit identity: this journey sends two turns, one per document.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.103" });
  await gotoDesk(page);

  const consoleErrors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => {
    consoleErrors.push(error.message);
  });

  await page.locator("#assistant-question").fill(QUESTION);
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-working"]')).toBeVisible();
  // Reload while the body is still streaming.
  await page.reload();
  await page.waitForLoadState("networkidle");

  // A reload is not a failure: no dialog, no fault, and nothing pretending the
  // interrupted turn is still there. Scoped to the page's own content: the dev
  // server's toolbar is its own live region and not part of the desk.
  await expect(page.locator('[data-testid="assistant-fault"]')).toHaveCount(0);
  await expect(page.locator('#main-content [role="alert"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-empty"]')).toBeVisible();
  // The transcript cleared, as the composer's note promises. That is the privacy
  // half: the question and the answer were never written anywhere that survives,
  // and the field does not keep the words either.
  await expect(page.locator(".assistant-question")).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-answer"]')).toHaveCount(0);
  await expect(page.locator("#assistant-question")).toHaveValue("");

  // The composer is usable and the desk answers the next question normally.
  const input = page.locator("#assistant-question");
  await expect(input).toBeEnabled();
  await expect(page.locator('[data-testid="assistant-send"]')).toBeDisabled();
  await input.fill("Which KEV entries are due soon?");
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(1);

  // Nothing was thrown or logged while the interrupted turn was dropped.
  expect(consoleErrors).toEqual([]);
});

test("390px: the attach, its thumbnail, the consent chip and its × all stay usable", async ({
  page,
}) => {
  // Its own rate-limit identity: this journey spends one turn.
  await page.setExtraHTTPHeaders({ "x-forwarded-for": "203.0.113.104" });
  await page.setViewportSize({ width: 390, height: 844 });
  await gotoDesk(page);
  await auditNoHorizontalOverflow(page, "phone attach: empty desk");

  // The attach control is a 44px target before it holds anything.
  const pick = await page.locator(".assistant-image-pick").boundingBox();
  expect(pick?.height ?? 0).toBeGreaterThanOrEqual(44);
  await page.setInputFiles('[data-testid="assistant-image-input"]', {
    name: "advisory.png",
    mimeType: "image/png",
    buffer: ADVISORY_PNG,
  });
  const preview = page.locator('[data-testid="assistant-image-preview"]');
  await expect(preview).toBeVisible();
  await expect(preview.locator("img")).toBeVisible();
  // Removing a staged file is a 44px target too.
  const stagedRemove = await page.locator('[data-testid="assistant-image-remove"]').boundingBox();
  expect(stagedRemove?.height ?? 0).toBeGreaterThanOrEqual(44);
  await auditNoHorizontalOverflow(page, "phone attach: staged");

  await page.locator("#assistant-question").fill("Which CVE ids are in this screenshot?");
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-answer"]')).toContainText(
    "canned answer of the test transport",
  );
  await auditNoHorizontalOverflow(page, "phone attach: sent");

  // The picture is inside the turn it was sent with, not a gallery beside it.
  const shot = page
    .locator('[data-testid="assistant-turn"]')
    .first()
    .locator('[data-testid="assistant-shot"]');
  await expect(shot).toBeVisible();
  const thumb = await shot.locator(".assistant-shot-thumb").boundingBox();
  expect(thumb?.height ?? 0).toBeGreaterThanOrEqual(96);
  await expect(shot.locator('[data-testid="assistant-shot-note"]')).toHaveText(
    "Attached with this question",
  );

  // The chip under the transcript: a labelled consent toggle and `×`. Both are
  // 44px boxes, which is the whole reason this journey exists.
  const chip = page.locator('[data-testid="assistant-image-context"]');
  await expect(chip).toBeVisible();
  const consent = page.locator('[data-testid="assistant-image-consent"]');
  await expect(consent).toBeVisible();
  // Unticked after a send: the next question decides on its own words.
  await expect(consent).not.toBeChecked();
  const consentBox = await chip.locator("label").boundingBox();
  expect(consentBox?.height ?? 0).toBeGreaterThanOrEqual(44);
  const remove = page.locator('[data-testid="assistant-image-context-remove"]');
  const removeBox = await remove.boundingBox();
  expect(removeBox?.width ?? 0).toBeGreaterThanOrEqual(44);
  expect(removeBox?.height ?? 0).toBeGreaterThanOrEqual(44);
  await auditNoHorizontalOverflow(page, "phone attach: chip");

  // The state the report shows: the thumbnail in the turn, the chip and the
  // composer under it, on one 390px screen.
  await page.evaluate(() => {
    document.querySelector('[data-testid="assistant-turn"]')?.scrollIntoView({ block: "start" });
  });
  await page.screenshot({ path: PHONE_ATTACH_SHOT });

  // Both are thumb-sized targets, not just boxes that measure well: tapping the
  // label flips the consent, twice, and tapping `×` ends the picture.
  await chip.locator("label").click();
  await expect(consent).toBeChecked();
  await chip.locator("label").click();
  await expect(consent).not.toBeChecked();
  await auditNoHorizontalOverflow(page, "phone attach: consent off");
  await remove.click();
  await expect(chip).toHaveCount(0);
  await expect(page.locator('[data-testid="assistant-image-removed"]')).toHaveText(
    "Screenshot removed — it will not be sent again.",
  );
  await expect(shot).toBeVisible();
  await auditNoHorizontalOverflow(page, "phone attach: removed");

  // The turn that carried it keeps its record; the next question carries nothing.
  await page.locator("#assistant-question").fill("What is the KEV deadline for agencies?");
  await page.keyboard.press("Enter");
  await expect(page.locator('[data-testid="assistant-turn"]')).toHaveCount(2);
  await expect(page.locator('[data-testid="assistant-shot"]')).toHaveCount(1);
  await auditNoHorizontalOverflow(page, "phone attach: next question");
});
