# v4 Image Context Truth — Plan

**Status:** researched, not implemented · **Scope:** the screenshot contract between composer,
transcript and request body · **Supersedes:** the retention decision in
`docs/plans/v4-attach-and-progress.md` §Measured evidence ("re-send the image on every turn"),
which 4.0.5 (`994ca50`) shipped without revisiting the label derived from it · **Evidence:** code at
`a16038e` plus a live capture of the deployed 4.0.5 at `http://100.124.184.116:3100/assistant`.

## Part A — what actually happens

### Code facts

| Fact                    | Where                                                                                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Send condition          | `src/components/assistant/AssistantDesk.tsx:300` — `if (attached !== null) body.image = …`                           |
| What `attached` is      | `AssistantDesk.tsx:261` — the live composer state, not a per-turn decision                                           |
| Thumbnail + label       | `AssistantView.tsx:207` + `:253-256` — note renders when `turn.image.id !== contextImageId`                          |
| `contextImageId` source | `AssistantView.tsx:786-787` — `image === null ? null : image.id`, i.e. **live chip state**                           |
| Removal                 | `AssistantDesk.tsx:450-452` — `setImage(null)`; the next request builds no `image`                                   |
| Server                  | `app/api/assistant/chat/route.ts:210` — forwards `body.image`; holds no state, so the whole behaviour is client-side |

There is **no** condition tied to the question and **no** per-turn flag: an attached image goes into every request body for as long as the composer holds it, and the note is derived from the _current_ chip — so it is applied retroactively to every historical turn, including the one that attached it.

### Live capture (deployed, 4.0.5)

`POST /api/assistant/chat` intercepted with Playwright; `image` = presence of the key, bytes = UTF-8 length of `image.dataUrl` (a 31 KB PNG, base64).

| #   | Question (as typed)                               | `image` | dataUrl bytes | body bytes | Thumbnail label on that turn              |
| --- | ------------------------------------------------- | ------- | ------------- | ---------- | ----------------------------------------- |
| 1   | Which CVE ids are in this screenshot? _(attach)_  | yes     | 41,538        | 41,641     | none — chip reads `screenshot in context` |
| 2   | What is the KEV deadline for federal agencies?    | **yes** | **41,538**    | 42,813     | none — chip reads `screenshot in context` |
| 3   | Explain that screenshot again.                    | yes     | 41,538        | 43,788     | none — chip reads `screenshot in context` |
| 4   | And what does the screenshot say the severity is? | **no**  | 0             | 4,379      | no thumbnail (removed before send)        |

Reported-state repro (× clicked while turn 2 streams): request 2 carried **41,538 bytes**, and turn 2
— the request that sent it — renders `No longer in context — this screenshot is not sent with later
questions`, while its answer opens "…For the two KEV-listed ids in the screenshot…". Turn 1, the
attach turn, carries the same false note. Both thumbnails go grayscale.

### Verdict

**(a) + (c), not (b).**

- **(a) confirmed.** The image is re-sent on every turn while the composer holds it: turn 2 asked a
  plain policy question and still shipped 41,538 bytes (`AssistantDesk.tsx:261`, `:300`).
- **(b) refuted.** Removal does clear the payload: turn 4 has no `image` key (`AssistantDesk.tsx:450`).
- **(c) confirmed, and it is the screenshot.** The label is computed from live chip state
  (`AssistantView.tsx:786-787` → `:207` → `:253-256`) and applied to history, so the moment the chip
  is cleared, a turn whose request _did_ carry the image is told it was not sent. Today the note is
  unreachable while an image is in context and appears on every historical turn after removal, so it
  is never a statement about the turn it sits under.

## Part B — the fix

**R1 — consent is per turn.** `image` becomes a staged payload plus a `sendImage` boolean; `body.image`
is set only when `sendImage` is true at send time. Replaces `AssistantDesk.tsx:300`.

**R2 — the attach turn sends it.** The first question after an attach defaults `sendImage` to true:
the user attached a picture to ask about it.

**R3 — a referential question re-sends it.** `refersToAttachment(question)`, case-insensitive,
word-boundary: `/\b(screenshot|image|picture|photo|attached|this|that|it)\b/i`. A false positive costs
≤912 prompt tokens (measured in `v4-attach-and-progress.md`); a false negative costs an answer about a
picture the model cannot see. That asymmetry, not the cost, decides it.

**R4 — the chip is the control.** `use screenshot in this question` — a real checkbox, the file name,
and ×. Checked for the question immediately after the attach only; reset to unchecked after every
send; the user ticks it to opt in later. Un-ticking is a choice about one question; × is removal of
the file.

**R5 — × is immediate and permanent.** It discards the payload, clears the staged image, and R3 may not
resurrect it: the only way back is re-attaching.

**R6 — labels state what happened.** The label is stored on the turn at send time, never derived from
composer state. A turn has a thumbnail only because its request carried the image, so it reads
`Attached with this question`. `Removed from context` is a composer-level note, shown once, after ×.
Delete the retroactive note (`AssistantView.tsx:253-256`), the `contextImageId` plumbing (`:786-787`,
`:207`) and the grayscale `data-in-context` styling, which reads as "not sent".

**Not changed:** the route, the transport, the body cap, and `refersToAttachment`'s home in `assistant-image.ts` (pure, unit-testable). Tests pinning today's behaviour move with it: `tests/assistant-desk.test.tsx:234`, `:250`, and `tests/e2e/assistant.spec.ts:663`.

### Acceptance checks

1. **AC1** attach turn → `Object.hasOwn(body, "image") === true`, `dataUrl` equals the rendered thumbnail.
2. **AC2** next turn, plain question → `Object.hasOwn(body, "image") === false`.
3. **AC3** "explain that screenshot" → present, byte-identical to AC1.
4. **AC4** after ×, "and what does the screenshot say?" → absent (R3 must not re-arm a removed payload).
5. **AC5** a sent turn reads `Attached with this question`; `No longer in context` appears nowhere.
6. **AC6** after ×: `Removed from context` exactly once, above the composer; history keeps its label.
7. **AC7** one journey, `the screenshot is sent only when the question asks for it`: attach → plain → referential → remove → ask, then a mid-stream × that asserts the in-flight turn's label does not flip.

## Part C — e2e coverage audit

`tests/e2e/assistant.spec.ts` is the only assistant spec: 23 journeys.

| Area                                                         | Journeys                               |
| ------------------------------------------------------------ | -------------------------------------- |
| Empty desk, suggestions, ledger                              | `:83`                                  |
| Stream: tool → text → citations                              | `:120`                                 |
| Stop mid-stream, keyboard-only stop                          | `:170`, `:253`                         |
| Working state, bar, counter, reduced motor                   | `:183`, `:227`                         |
| Pinned record scope + removal                                | `:273`                                 |
| Disabled desk, 390px layout, a11y audit                      | `:296`, `:309`, `:338`                 |
| Rendered answer: table, headings, unverified                 | `:345`, `:397`, `:850`                 |
| Screenshots: pick/preview/send, retained, phone audit, guide | `:504`, `:595`, `:691`, `:734`, `:772` |
| Compare, brief, follow-up, entry points                      | `:805`, `:888`, `:940`                 |

| Gap                                      | Today                                           | Verdict   | Why                                                                                      |
| ---------------------------------------- | ----------------------------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| Image truth across turns (this bug)      | none — `:595` asserts the sticky re-send        | close now | The reported defect; AC1–AC6 land here                                                   |
| × mid-stream: label on a sent turn       | none                                            | close now | The exact screenshot; needs no app change, only AC7's second half                        |
| Error mid-stream, then retry             | none                                            | close now | `networkFault` (`AssistantDesk.tsx:96`) is unproven; abort the SSE body via `page.route` |
| Double-send prevention                   | none                                            | close now | One POST under double Enter is an invariant, and one assertion                           |
| Refresh mid-stream                       | none — copy claims "a reload starts clean"      | close now | Also proves the image is never persisted; cheapest privacy proof                         |
| 390px attach + chip compose flow         | `:309` layout, `:691` retained shot only        | close now | R4 adds the widest control on the narrowest screen                                       |
| Rate-limit countdown in a browser        | unit only (`tests/assistant-view.test.tsx:262`) | later     | 11 streamed turns for a state already asserted at unit level                             |
| Daily / session budget state             | unit only (`:274`, `:287`)                      | later     | Needs a seeded ledger fixture; no new client claim                                       |
| Compare through to a rendered comparison | `:805` stops at the request                     | later     | The answer path is the same stream journey                                               |
