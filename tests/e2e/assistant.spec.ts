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

import { expect, test, type Page } from "@playwright/test";

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
  // One image per turn: the composer is clean again for the next question.
  await expect(preview).toHaveCount(0);

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
