# v4 Attach Guidance & Progress States — Plan

**Target release:** 4.0.5 · **Status:** shipped on `main` — P1–P5 done, tagged `v4.0.5` · **Scope:** three assistant
UX defects — a streaming state that reads as stopped, no guidance on what a screenshot is good for,
and an attachment that vanishes from the record · **Predecessor:**
`docs/plans/v4-ux-hardening.md` (4.0.3–4.0.4) · **Design owner:** `DESIGN.md` §6 Assistant. P1–P3 are
**decisions, not options**, and Part A is measured rather than assumed.

**Shipped:** P1 `210b155` · P2 `34617ad` · P3 `994ca50` · P4 `ce47df8` · P5 release `4bcafb6`
(tag `v4.0.5`), on `main`. `package.json`/`package-lock.json` (version only), `CHANGELOG.md`,
`README.md` and `CLAUDE.md` are at 4.0.5. Gates on 2026-11-25: lint, typecheck and build clean;
`npm test` 1106 passed / 3 skipped (network-gated); `npx playwright test` 161 passed / 0 skipped;
`npm audit --omit=dev` clean. One deviation from P2 item 3: `docs/images/attach-example.png` shipped
with the guidance in `34617ad`, and `docs/images/assistant-attached.png` was not captured as its own
frame: the turn thumbnail and the context chip are shown in `docs/images/assistant.png`, the working
state in `docs/images/assistant-progress.png`, and only the removal path stays asserted by the e2e
suite rather than photographed.

## Measured evidence

**Method.** `POST $AI_BASE_URL/chat/completions`, `AI_MODEL=deepseek-v4.1-flash`, `max_tokens: 32`,
prompt `Name the CVE ids in this screenshot.`, one request carrying a single `image_url` part and one
without it. The gateway requires `x-opencode-session` (`400 MissingSessionID` otherwise).

| Image                     | Bytes   | `prompt_tokens` | Δ image  | Δ list cost |
| ------------------------- | ------- | --------------- | -------- | ----------- |
| none — baseline, twice    | —       | 39 / 39         | —        | —           |
| advisory panel, 600×200   | 12.4 KB | 233             | **+194** | $0.0000291  |
| full screenshot, 1400×900 | 86.8 KB | 811             | **+772** | $0.0001158  |
| near-limit PNG, 760×660   | 1.50 MB | 361             | **+322** | $0.0000483  |

1. **The image is sent once, then dropped.** `buildConversation` (`src/lib/ai/turn.ts:229`) puts the
   `image_url` part on the last user message only, and `AssistantDesk` clears it at `:268` the moment
   the send starts. `buildHistory` (`:65`) sends text only. So a follow-up turn genuinely has no image
   in context — complaint 3 is a code fact, not an impression.
2. **An image costs 194–772 prompt tokens**, plus the ~140-token `VISION_INSTRUCTION`
   (`src/lib/ai/prompt.ts:171`) that is re-added whenever an image is present: ≤ 912 tokens and
   ≤ $0.00012 per turn, about 0.002% of the $5 daily cap. Cost tracks **pixels, not bytes** — the
   1.50 MB image is cheaper than the 86.8 KB one because it is smaller in area.
3. **Keeping it fits, with 1.0 MiB to spare.** Body cap 3,145,728 (`body.ts:26`), image cap 1,572,864
   (`:35`). A maximum image is `ceil(1,572,864/3)*4` = 2,097,152 base64 chars + a 22-char prefix =
   **2,097,174 bytes**; headroom **1,048,554 bytes** for the envelope and the history, which the client
   already caps at `MAX_HISTORY_CHARS = 11_000`. The image is a content part of the last user message,
   not a message, so `ASSISTANT_MAX_MESSAGES = 12` (`:29`) is untouched. Measured: the 1.50 MB image
   built a 2,008,256-byte body — 1.14 MB under the cap.

**Retention decision: re-send the image on every turn while it is in context.** 772 tokens is under
the 1,500-token threshold, so the referential heuristic ("screenshot", "this", "that") is not needed:
one sentence of behaviour, no silent loss on a follow-up, and no new worst-case request — the attach
turn already sends exactly that payload once.

## P1 — progress that visibly moves — **done** (`210b155`)

1. **The bar animates instead of advancing by a fake percentage.** Delete the computed width
   (`AssistantView.tsx:205`, `22 + tools*18`); `.assistant-progress` (`app/ui.css:5637`) becomes a 2px
   track with a 30%-wide segment under `animation: assistant-sweep 1.1s ease-in-out infinite`
   (`translateX(-100%)` → `translateX(320%)`), and carries `is-running`. It still renders only while
   the answer is empty — once prose arrives the prose is the movement — so
   `tests/assistant-view.test.tsx:147` keeps its meaning.
2. **One working region, in the composer foot.** The row that already holds the Stop button
   (`AssistantView.tsx:527`) becomes the region: stage text from `activity` (`reading 25 records…`,
   `writing…`), then the elapsed counter, then Stop, in that order. It is `role="status"`
   `aria-live="polite"`; the counter is `aria-hidden="true"` so a tick is never announced and the
   region's accessible text changes only when the stage does. The turn's `assistant-activity` line is
   removed: two copies of the same stage string on one screen is noise, and the transcript's record of
   what ran is the ledger. The mid-stream screenshot (`tests/e2e/assistant.spec.ts:372`) moves with it.
3. **The elapsed counter proves liveness even when nothing else moves.** Interval-driven state at
   250 ms from send until settle or Stop; renders `0.4s` under ten seconds and `12s` after — tenths
   exactly where a wait feels static, whole seconds once it is obviously long. Tabular figures, no
   layout shift.
4. **The composer is visibly working, not a different page.** The form gains `is-working`: the well's
   border steps to `--ui-ink-3` and its fill to `--ui-surface-raised`, the working row sits on a 2px
   left rule. Existing tokens only — no new colour.
5. **Reduced motion keeps proving liveness.** The global `animation-duration: 0s !important`
   (`app/ui.css:1540`) would otherwise freeze the bar mid-sweep and read as broken, so an explicit
   `@media (prefers-reduced-motion: reduce)` block turns the bar into a static hatched track at full
   width; the counter is JS state, keeps ticking, and carries the liveness alone.

**Accept.** e2e: the working region is visible after send and two samples of the counter 400 ms apart
differ; the bar carries `is-running` and a computed `animation-name` other than `none`. With
`page.emulateMedia({ reducedMotion: "reduce" })` the computed `animation-duration` is `0s` **and** the
counter still changes. Unit: the region's accessible text equals the stage string with the counter
stripped, and the counter is `aria-hidden`.

## P2 — tell people what to attach — **done** (`34617ad`)

1. **A "What works" disclosure under the attach control**, inside `.assistant-image` beside the
   existing format note (`AssistantView.tsx:437-478`). A native `<details>` with a 44px `<summary>` —
   keyboard operable with no JS, open on Enter and Space for free.
2. **The copy, asserted verbatim** (a copy regression is a failing test, not a review note):
   - Purpose: "The image is only used to find CVE ids. Each id is then checked against this dataset,
     and an id that does not resolve is reported as not here."
   - Works: a vendor advisory page showing a CVE id · an NVD or CVE record page · a scanner report or
     ticket listing CVEs · a PDF page screenshot that carries a CVE id.
   - Does not work: a game scoreboard or a photo · a dashboard with no CVE id, vendor or product name.
   - The refusal, stated as correct behaviour: "If the image has no CVE id in it, the answer says so.
     That is the desk working, not a failure."
3. **`docs/images/attach-example.png`** — 720×360, our own styling and palette, no third-party
   artwork: a header strip `SECURITY ADVISORY · ADV-2026-0114`, three rows of
   `CVE-YYYY-NNNNN · vendor product · CVSS x.y`, one "fixed in" line. Two ids are widely-present
   real ones (`CVE-2021-44228`, `CVE-2023-44487`); the third (`CVE-2026-0001`) is deliberately absent
   from any snapshot, so the caption can say it demonstrates the "not in the dataset" path. ≤80 KB.
   Referenced from `README.md` in the assistant section, next to the screenshot-intake row (`:71`).
   `docs/` is not served by the app, so the disclosure itself stays text-only.

**Accept.** The disclosure exists, opens by keyboard alone (e2e: Tab to the summary, Enter, content
visible, Escape/Enter closes), and its copy names ≥3 useful sources and ≥2 useless ones, asserted as
strings in `tests/assistant-view.test.tsx`. axe clean with it open at 390px.

## P3 — the image stays visible and in context — **done** (`994ca50`)

1. **The turn keeps a thumbnail, not the payload.** `AssistantTurn` gains
   `image: { name, mime, size, thumb } | null`, where `thumb` is a downscaled data URL (≤480 px wide,
   WebP q0.75, typically <40 KB) produced once at attach time by a `toThumbnail()` in
   `assistant-image.ts`. The full-size data URL is **not** kept on the turn: ten turns × 2.1 MB of
   base64 is 21 MB of retained string for a record that needs to be recognisable, not re-sendable.
2. **It renders inside the user's turn.** Under `.assistant-question`, a `<details>` whose summary is
   the 72×48 thumbnail plus `Attached screenshot · 41 KB`, expanding in place to the full-width
   thumbnail. No modal: no focus trap, no scroll lock, and it reads as part of the question.
   `alt="Attached screenshot: {name}"` on the summary image, `alt=""` + `aria-hidden` on the expanded
   copy because the summary already names it. No `data:` in `title`, `alt`, `aria-label` or any error
   string — the only `src` is the thumbnail's own, and nothing is logged.
3. **A context chip above the composer.** The `.assistant-context` row that carries `about` gains a
   sibling: `image in context · shot.png · ×` (`data-testid="assistant-image-context"`). Removing it
   stops the send on the next turn and clears the turn's thumbnail source.
4. **Retention is one line of code.** `setImage(null)` after send (`AssistantDesk.tsx:268`) becomes a
   move into `imageContext`; `body.image` (`:283`) is set from `imageContext` on every turn. Per
   Part A: every turn, no heuristic.
5. **Privacy copy follows the behaviour.** `AssistantView.tsx:548` becomes: "The transcript and any
   screenshot live in this tab and nowhere else — a reload starts clean, and neither is written to
   this browser's storage."
6. **Two existing assertions change meaning, deliberately.** `tests/e2e/assistant.spec.ts:466` asserts
   the composer is clean after send; it becomes "the intake is empty **and** the context chip is
   present". `latestUserMessage` (`app/api/assistant/_lib/fake-transport.ts:156`) returns `""` when the
   last user message's content is an array, so a retained image would silently disable the `as a table`
   and `with a heading` markers on every later turn — it must join the `text` parts. Without that fix
   P3 breaks three journeys for a reason unrelated to images.
7. **The session estimate stays image-blind, recorded.** `estimateSessionTokens` (`body.ts:369`) sums
   text characters, so eight retained-image turns are ~6,200 real tokens the 60,000-token session
   estimate never sees. Not fixed: that cap is a courtesy notice, not a control
   (`v4-ux-hardening.md` §4 D1), and the daily ledger still bounds money.

**Accept.** e2e: after attach + send the thumbnail is inside the turn and its summary names the file;
a follow-up request's body contains an `image_url` part (`body.image.dataUrl` matching
`^data:image/png;base64,`); removing the chip makes the next request carry no `image` key. Unit: a turn
with an image renders the summary and alt text, a turn without one renders nothing, and no `data:image`
substring appears in `alt`/`title`.

## P4 — tests — **done** (`ce47df8`)

| Layer | File                                                 | New assertions                                                                    |
| ----- | ---------------------------------------------------- | --------------------------------------------------------------------------------- |
| unit  | `assistant-view.test.tsx`, `assistant-image.test.ts` | working region + `aria-hidden` counter, disclosure copy, thumbnail, `toThumbnail` |
| e2e   | `tests/e2e/assistant.spec.ts`                        | counter increases, bar animates, reduced motion ticks, retention, keyboard        |
| axe   | `tests/e2e/a11y-mark-targets.spec.ts`                | disclosure open at 390px, thumbnail expanded, mid-stream state captured           |

## P5 — docs, screenshots, release 4.0.5 — **done** (`4bcafb6`, tag `v4.0.5`)

`README.md` (intake row, the example image, the context sentence, then three assistant frames),
`CHANGELOG.md` (`## 4.0.5`), `DESIGN.md` §6 (the working state and the attachment rule),
`docs/api/README.md` (one line: the image is a content part of the last user message and may be
re-sent), `package.json` `4.0.5`. Screenshots, all 1440×900 dark frames from a local 4.0.5 e2e server
with `AI_FAKE_TRANSPORT=1` against the dense twelve-record fixture: `docs/images/assistant.png`
re-captured with the attached thumbnail inside the turn and the `screenshot in context` row
(119,487 bytes), new `docs/images/assistant-progress.png` (mid-stream sweep, stage and elapsed
counter, 111,823 bytes), and `docs/images/assistant-compare.png` refreshed for the `What works`
disclosure (123,522 bytes). Their captions state exactly what each frame shows. Release commit
`4bcafb6`, tag `v4.0.5`; the frames, their README captions and this plan's closure landed in the
follow-up docs commit. Docs gate: `npx prettier --check README.md
docs/plans/v4-attach-and-progress.md` clean, `npm run lint` unchanged.

**Live verification passed with three measured facts.** Under `prefers-reduced-motion: reduce` the
bar's segment still declares `animation: assistant-sweep` at `1.1s` while the global reduced-motion
rule collapses its duration to `0s`, and the elapsed counter changed between two samples 400 ms apart
— liveness does not depend on the sweep. A follow-up request body carried a 49,748-byte `dataUrl`
while the context chip was present, and carried no `image` key once it was removed — retention is on
the wire, not just in the markup. `/assistant` at 390px had 0 horizontal overflow.

## Risks

- **Image tokens per turn.** Measured, not estimated: 194–772 for the image, ≤912 with the vision
  instruction, ≤$0.00012 list per turn. Re-sending on every turn is the cheap branch; the referential
  heuristic stays in this plan only as the fallback if a future model prices images per byte.
- **Request size against the 3 MiB body cap.** 2,097,174 bytes of image leaves 1,048,554 bytes for a
  history already capped at 11,000 characters. Tight but arithmetic, and unchanged by retention: the
  attach turn sends the same payload today. A larger image cap would need the body cap raised with it.
- **Model refusal on an out-of-scope image is correct.** A game screenshot was declined and the
  answer said why; that is the desk working. P2 states it in the disclosure so the UI cannot imply a
  bug, and P1 must not turn a refusal into a red error state.
- **Two live regions.** Avoided by design: the composer row is the only `role="status"`; the turn's
  bar is `aria-hidden` decoration, and the ledger's row counts are the accessible record.
- **Fake-transport regression.** The `latestUserMessage` fix in P3 item 6 is a prerequisite, not a
  cleanup — without it the retained image silently changes what the browser suite exercises.

## Non-goals

- No persistence of the image: no IndexedDB, no `localStorage`, no session id — a reload clears it.
- No image history beyond each turn's thumbnail; no gallery, no multi-image turns, no raised limits.
- No modal viewer for the thumbnail: `<details>` in place, one left edge.
- No OCR or extraction change — the vision instruction and the resolve-every-id rule stay as they are.
- No new colours; the working state uses `--ui-ink-3`, `--ui-surface-raised`, `--ui-rule-soft`.
