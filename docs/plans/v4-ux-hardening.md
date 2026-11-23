# v4 UX & Guardrail Hardening — Plan

**Target release:** 4.0.3 · **Status:** P1–P5 shipped (see the **Shipped** line under each
phase); P6 is in progress — its docs half is committed, its screenshots, image and deploy are still
pending · **Scope:** no new capability — density,
copy, renderer coverage, and the guardrail gaps the live 4.0.2 instance exposed · **Predecessor:**
`docs/plans/v4-ai-chat.md` (ships 4.0.0–4.0.2) · **Design owner:** `DESIGN.md` §6 Assistant, §7.0

A–G are **decisions, not options**. §6 is the commit sequence that applies them; nothing in §1–§5 is
done until its phase has a commit sha. Every symptom is measured on 4.0.2, located in the file that
causes it, and read from the code rather than inferred.

## Evidence as found

| Symptom, as reported                                                             | Where it comes from                                                                                       | Reading of the code                                                                    |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| One call renders 12 chips in one row while its own line says "25 rows"           | `ASSISTANT_TOOL_ID_SAMPLE = 12`, `src/lib/ai/turn.ts:66`, consumed at `:485` (`returnedIds.slice(0, 12)`) | `rows` is the real count; `ids` is a **display sample**. Both print, neither explains. |
| A two-call answer shows 20 rail chips **and** 15 of the same chips under "Cited" | `AssistantLedger.tsx` chips `line.ids`; `AssistantView.tsx` separately chips `turn.citations`             | The same ids render twice from two arrays, with nothing saying which view is which.    |
| The rail scrolls independently of the page at higher call counts                 | `app/ui.css:5692-5702`: `max-height: calc(100vh - …)` + `overflow: auto` (810px live)                     | An inner scrollbar competes with the page; the page has two scroll contexts.           |
| `###` and `---` render as literal text                                           | `render-answer.tsx:renderBlocks` has no heading, rule or quote branch                                     | Not an escaping bug — those constructs are outside the whitelist.                      |
| An oversized body, a second image and an oversized image all answer `400`        | `app/api/assistant/_lib/body.ts:97,126,175` → `BAD_REQUEST`/`BAD_IMAGE` → default 400                     | The refusals are correct; the statuses under-report them.                              |
| `AI_MAX_TURNS` reads like a turn cap                                             | parsed at `src/lib/ai/config.ts:158`, asserted in `tests/ai-config.test.ts:24`                            | **No code consumes it.** The enforced message cap is `ASSISTANT_MAX_MESSAGES = 12`.    |

## 1. Density — the rail (A)

1. **Per call, 6 chips then a disclosure.** An entry renders `line.ids.slice(0, 6)`; if more exist, a
   44px `+N more` button (`GraphView`'s existing `+N more · view all` pill is the pattern) reveals the
   rest **in place**, per entry, once — never a new surface. Expanded state lives in
   `AssistantLedger`, keyed by `line.id`, so a later delta's re-render cannot collapse it.
2. **Never silently cap.** The rows label is derived: `rows === 0` → `no rows`; `!ok` → `failed`;
   `ids.length === rows` → `25 rows`; `ids.length < rows` → `25 rows · 12 ids available`. The last
   form is the one the live rail lacks, and it is why the two numbers read as a contradiction.
3. **Fix the sample where it is cheap, explain it where it is not.** Raise
   `ASSISTANT_TOOL_ID_SAMPLE` to **25** — the row cap of `search_cves` and `list_priority`, so the
   common call states one number; `kev_window` (cap 50) still needs form three. Cost: 25 ids of ~15
   chars on one SSE frame, under 1 KB.
4. **Calls: 3 then `See all N calls`.** The rail lists the transcript's first three calls; `See all 7
calls` expands the rest. `no rows` and `failed` calls are **pinned above the disclosure** and
   always visible: an empty result is the evidence that a question had no answer.
5. **The rail stops scrolling.** Remove `max-height` and `overflow` at ≥1024px, keep `position:
sticky`. The cap is content — 3 calls × (line + args + 6 chips) plus the legend — not a scrollbar.
   At ≤1023px it stays a folded `<details>` under the answer, unchanged.
6. **"Cited" collapses to one line.** `<details><summary>15 records cited</summary>` opens to the
   chips, closed by default at every width. It stays because it is the turn's union while the rail is
   per call; the summary line says which is which.

**Accept.** A 25-row `search_cves` renders 6 chips, `+19 more`, and a line reading exactly `25 rows`;
a 50-row `kev_window` reads `50 rows · 25 ids available`; expanding shows 25 in place. A 2-call turn
renders 2 rail entries and one `15 records cited` summary, no chip visible until it opens. A 7-call
turn shows 3 plus `See all 7 calls`, and a `no rows` call in position 5 is visible unexpanded. At
1440×900 the ledger computes no `overflow` and no `max-height`.

## 2. Comprehension (B)

1. **One legend line, replacing the current note.** Above the list: `Evidence · 4 tool calls`, then
   "Each line is one lookup the server ran. **Rows** are the records it returned; **chips** are the
   records you can open." The three-sentence `assistant-ledger-note` paragraph is deleted.
2. **A three-sentence "How this works" disclosure under the subtitle.** "Answers come from tool calls
   over this deployment's own dataset — no model memory, no web search [unless the fallback is on].
   Every number is quoted from the records those calls returned, and a record that is not here is
   reported missing, never guessed. Nothing you type is stored: the transcript lives in this tab and
   a reload starts clean." The `page-lede`'s second sentence moves here, so the lede is one sentence
   and the bracket renders only when `AI_WEB_FETCH_ENABLED` is on (one new page fact).
3. **Five `HelpTip`s, meaning only, never implementation** (`src/components/ledger/HelpTip.tsx`):
   | Term                     | Sits on                            | Says                                                                                                                                                         |
   | ------------------------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
   | `rows`                   | the legend                         | "How many records the lookup returned. A lookup that stops at its own limit says so, and the count is the limit, not the match total."                       |
   | `tool call`              | the legend                         | "One question the server asked the dataset on your behalf. The answer is written from these results only."                                                   |
   | `cited`                  | the citations summary              | "Records the answer's numbers came from. The same ids appear in the rail under the call that returned them."                                                 |
   | `unverified ids`         | the `.assistant-unverified` line   | "An id the answer named that the records did not contain. It is text, not a link, because this dataset cannot confirm it."                                   |
   | `session / daily budget` | the budget fault panel's meta line | "A session budget counts this conversation; the daily budget counts everyone on this deployment and resets at 00:00 UTC. The panel names which one ran out." |
4. **Empty state names the edges.** Under the suggestions, one line: "Ask about KEV additions, EPSS
   scores, CVSS, CWE or exploit references in this snapshot. It does not forecast, and it will not
   answer from anywhere else." The `assistant-suggestions-empty` copy gains the same second sentence.

**Accept.** No tip repeats a file name or an env var. The legend is one sentence pair, the disclosure
is exactly three sentences, and every new string is asserted in `tests/assistant-view.test.tsx`: a
copy regression is a failing test, not a review note. axe clean with every tip open at 390px.

## 3. Renderer gaps (C)

Three block constructs in `render-answer.tsx`, inside the existing escape-first pass — every leaf
stays a React text child, no `dangerouslySetInnerHTML`, `safeHref` untouched.

1. **Headings.** `^(#{1,4})\s+(\S.*)$` → `h3` for one to three hashes, `h4` for four. The level is
   **clamped inside the answer** (the page owns `h1`), so a model heading never outranks the page and
   never skips a level. Trailing `#`s are stripped; `###` with no text stays text.
2. **Horizontal rules.** `^ {0,3}([-*_])(?:\s*\1){2,}\s*$` on a line with no `|` → `<hr>`. The pipe
   check is what keeps it from colliding with a table's separator row; `isTableStart` already
   requires a header pipe, so the two rules cannot both fire.
3. **Blockquotes.** Consecutive `^ {0,3}>\s?` lines become one `<blockquote>`, blank-line-separated
   runs becoming paragraphs inside it, inline constructs applied. A `>` mid-line stays text.

**Degradation is the rule.** An unbalanced marker renders as the characters the model wrote: a lone
`**`, `*` or `` ` ``, and `[label](target` with no closing paren (both already true — pin them with
tests), and a heading marker with no text. **One behaviour changes:** an unterminated fenced block
renders as literal text _including its backticks_ until the closing fence arrives, instead of becoming
a `<pre>` at once (`renderBlocks` does the latter today). Cost, recorded: a streaming answer shows
three backticks for the length of the block, then becomes code in one step; in exchange no half-built
element is ever on screen and the streaming and settled renders agree on what a block is.

**Accept** (`tests/assistant-render.test.tsx`), one test per row: `#`→`h3`, `###`→`h3`, `####`→`h4`,
`###` alone stays text, `---`/`***`/`___`→`hr`, `---` in a table's separator position still renders a
table, `> quoted`→`blockquote`, a two-paragraph quote, `>` mid-sentence stays text, lone `**` literal,
unterminated fence literal then `<pre><code>` once closed, `<script>` in a heading stays text, and an
id inside a heading links only when cited (policy unchanged).

## 4. Abuse resistance (D)

| Limit                       | Value                                         | Enforced at                                                                  | State                           |
| --------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------- |
| Per-IP burst                | 10 / minute                                   | `app/api/assistant/_lib/rate-limit.ts`, first statement in `POST`            | enforced, `429` + `Retry-After` |
| Per-IP sustained            | 60 / hour                                     | same module, both windows consumed together                                  | enforced                        |
| Request body                | 3 MiB (`ASSISTANT_MAX_BODY_BYTES`)            | `readAssistantBody`: `Content-Length` **and** a counted stream abort         | enforced, **reported `400`**    |
| Messages per turn           | 12 (`ASSISTANT_MAX_MESSAGES`)                 | `validateAssistantBody`                                                      | enforced, `400`                 |
| Characters per message      | 2,000 (`ASSISTANT_MAX_MESSAGE_CHARS`)         | `validateAssistantBody` + `preScreen({ maxChars })`                          | enforced, `400`/`BAD_QUERY`     |
| Characters per conversation | 12,000 (`ASSISTANT_MAX_TOTAL_CHARS`)          | `validateAssistantBody`                                                      | enforced, `400`                 |
| Images                      | 1 × 1.5 MiB (`1_572_864`), magic-sniffed      | `body.ts` image validation                                                   | enforced, **reported `400`**    |
| Tool rounds                 | 4 (`ASSISTANT_MAX_TOOL_ROUNDS`, `turn.ts:52`) | the tool loop                                                                | enforced                        |
| Session tokens              | 60,000 (`AI_SESSION_BUDGET_TOKENS`)           | route step 7 vs `estimateSessionTokens` = `chars ÷ 4` of client-sent history | **estimated**                   |
| Daily spend                 | $5 (`AI_DAILY_BUDGET_USD`)                    | `ai_usage` row + `ledger.dailyBudgetExceeded()` before the turn              | enforced, persistent            |
| Answer tokens               | 4,096, floor 512                              | `config.ts` at boot                                                          | enforced                        |
| Citation ids                | 200 / turn (`ASSISTANT_CITATION_CAP`)         | `turn.ts`                                                                    | enforced                        |
| Provider wait               | 45 s, 20 s idle                               | `config.ts`, `client.ts`                                                     | enforced                        |
| Concurrency                 | 32, shared with the read API                  | `acquireConcurrencySlot`, held until the stream closes                       | enforced                        |

**Gap D1 — the session cap is an estimate over client-shaped input.** The server _does_ check a
budget, but a "session" is whatever history the client posts, and the estimate is `chars ÷ 4` of it:
an empty history resets the budget to zero. `AI_MAX_TURNS` is parsed, asserted in one test, and
**read by nothing**. Decision: **no server-side session identity** — that is the persistence §7
forbids. Instead: keep the budget and relabel it in the fault copy as a courtesy notice, not a
security control; state in `docs/api/README.md` that the only money bound is the per-IP window plus
the daily ledger; delete `AI_MAX_TURNS`, because a knob no code reads is a lie with a default. The
enforced message cap of 12 stays.

**Gap D2 — repeated identical questions are uncapped.** Decision: **leave it uncapped, recorded.**
≈$0.002 per turn puts one client's ceiling near $0.12/hour at 60/hour, and the $5 daily ledger bounds
the deployment. A repeat cache would store the question or a hash of it — a fingerprint of what a
reader asked, the one artefact §7 rules out — and re-asking is legitimate traffic.

**Gap D3 — a concurrent burst cannot bypass the limiter.** Already true, now proven:
`reserveAssistantRateLimit` is the route's first statement and increments both windows
**synchronously**, so N in-flight requests on one event loop consume N tokens and the 11th is
refused. The residual limit is the v1 limiter's own: state is process-local, so N instances allow
10N/minute. Recorded, not fixed.

**Accept.** (1) `429` with `Retry-After` on the 11th request — the test at
`tests/ai-route.test.ts:275` stays, and a new test fires **20 concurrent** `POST`s and asserts exactly
10 non-`429` bodies. (2) A 3 MiB + 1 byte body answers **`413`** with `details.maxBytes`: add
`PAYLOAD_TOO_LARGE` to `ErrorCode` → `413` rather than reusing `BAD_REQUEST`'s `400`. (3) A second
image answers **`422`** (`BAD_IMAGE` → `422`); an image over 1.5 MiB answers **`413`**. (4) The daily
check runs **before** any upstream call: extend the existing `AI_BUDGET_EXHAUSTED` tests to assert the
transport spy's `calls` is empty on both the daily and the session branch.

## 5. Web fallback (E)

**Behaviour, confirmed in code.** `fetch_authoritative` enters the tool list only when
`AI_WEB_FETCH_ENABLED` is on (`tools.ts:498`); off, it is absent **and** refused by name with
`WEB_FETCH_DISABLED` (`:1264`). `prompt.ts:118` states the model's two conditions: the dataset cannot
answer, and one fetch per turn. The guard is exact-host `WEB_FETCH_ALLOWLIST` (`:1051`: `cve.org`,
`www.cve.org`, `nvd.nist.gov`, `services.nvd.nist.gov`, `www.cisa.gov`, `www.first.org`,
`cwe.mitre.org`), `https:` and GET only, 8 s, 256 KB, at most one redirect re-checked against the
allowlist (`:1182-1185`), capped body and extracted text (`:1203-1205`), returned as untrusted data
and cited as a `web` chip carrying its host.

**Accept.** (a) A live check on 4.0.3 asks something this snapshot cannot hold (a CVE's current
vendor advisory text): the turn shows one `fetch_authoritative` line, the answer cites the URL as a
chip marked `web`, and no second call carries `source: "web"`. (b) A unit test asserts
`fetch_authoritative` is refused with `WEB_FETCH_DISABLED` when `AI_WEB_FETCH_ENABLED=false`, even
when asked for by name. (c) A test asserts the fallback fires **at most once per turn**, so "one per
turn" is code, not prompt hope.

## 6. Phases (F)

Each phase: work, acceptance, commit. Order is dependency, not effort.

**P1 — rail density.** §1 items 1–6: sample to 25, per-call and per-transcript disclosure, the
`25 rows · 12 ids available` label, no `max-height`/`overflow`, "Cited" folded. **Accept:** §1's four
acceptance sentences in `tests/assistant-view.test.tsx`, axe clean on a 7-call transcript, no
horizontal overflow at 390px. **Commit:**
`feat(assistant): cap the rail by calls and records, not by a scrollbar`

**Shipped:** `435fd9a` — `feat(assistant): cap the rail by calls and records, not by a
scrollbar`. Note: `ASSISTANT_TOOL_ID_SAMPLE` stayed at **12**, not the 25 this plan proposed.
The honest label (`25 rows · 12 ids available`) is what removes the contradiction, so the
cheaper fix won and the row/ids distinction is now stated instead of widened.

**P2 — comprehension copy.** §2: legend, "How this works", five `HelpTip`s, empty-state edges, the
`webEnabled` page fact. **Accept:** every new string asserted; no tip names an env var or a file; the
disclosure is three sentences; axe clean with all tips open at 390px. **Commit:**
`feat(assistant): explain the rail in one legend, one disclosure and five tips`

**Shipped:** `202f469` — `feat(assistant): explain the rail in one legend, one disclosure and
five tips`.

**P3 — renderer gaps.** §3: headings, rules, quotes, and the fence degradation change. **Accept:**
every §3 render test passes with the existing link-policy tests untouched. **Commit:**
`feat(assistant): render headings, rules and quotes and degrade broken markers to text`

**Shipped:** `e359118` — `feat(assistant): render headings, rules and quotes and degrade broken
markers to text`. The last acceptance row (a heading that skips a level) was not caught until
P4; `6fc3778` stops the skip and adds the assertion.

**P4 — guardrail gaps.** §4: `PAYLOAD_TOO_LARGE` 413, `BAD_IMAGE` 422, the concurrent-burst test, the
budget-before-upstream assertions, `AI_MAX_TURNS` deleted, the API doc paragraph. **Accept:** §4's four
items. **Commit:** `fix(assistant): answer 413 and 422 for oversize bodies and images, and prove the burst cap`

**Shipped:** `6fc3778` — `fix(assistant): answer 413 and 422 for oversize input, prove the burst
cap, and stop skipping a heading level` (one commit, both concerns: the heading-level skip is
§3's last acceptance row). The suite-health fix for the wall-clock-dependent fixtures landed
separately as `94a13ab` — `fix(tests): stop the radar/replay fixtures depending on the wall
clock` — so a retained-checkpoint assertion no longer expires with the calendar.

**P5 — web-fallback proof.** §5: the once-per-turn assertion, the disabled-tool test, the live check
with a screenshot of the ledger line and the `web` chip. **Accept:** §5 (a) (b) (c). **Commit:**
`test(assistant): prove the web fallback runs once and only when enabled`

**Shipped:** `eba2175` — `feat(ai): fetch machine-readable sources instead of client-rendered
pages`. The commit does more than prove the fallback: the live check showed the model fetching a
client-rendered page whose extracted text was one line of chrome, so `fetch_authoritative` now
returns `application/json`/`*+json` as pretty-printed JSON and reports `title` plus
`mayBeClientRendered` for a short HTML body. The once-per-turn and disabled-tool assertions ship
with it, and the prompt now names the NVD API 2.0, CISA KEV and FIRST EPSS endpoints ahead of the
page, kept honest by an allowlist-parity test.

**P6 — docs, screenshots, release 4.0.3.** `DESIGN.md` §6 Assistant (density rules, legend, citation
summary), `README.md`, `CHANGELOG.md`, `docs/api/README.md`, `CONTEXT.md`, `.env.example`
(`AI_MAX_TURNS` gone), version `4.0.3`, screenshots at 1440px and 390px, tag, image, deploy.
**Accept:** `lint`, `typecheck`, `build`, `npm test`, `npx playwright test` and `format:check` clean,
`.env.example` still covers every `process.env` read, and a live turn shows the new rail. **Commit:**
`docs: document the hardened assistant and release 4.0.3`

**Status:** pending. The docs half ships now — `CHANGELOG.md` (`## 4.0.3`), `README.md`,
`CLAUDE.md`, `docs/api/README.md`, version `4.0.3` — committed as `Release 4.0.3` and tagged
`v4.0.3`. **Not done and not claimed:** no image was built or pushed, nothing was deployed, and no
new screenshots were captured. `DESIGN.md` §6 and `CONTEXT.md` are unchanged by this commit; a
screenshot pass needs a running instance.

## 7. Non-goals (G)

Recorded so a later session does not "improve" into them.

- **No chat bubbles**, no avatars, no speaker indentation — the one left edge stays.
- **No streaming reasoning text.** Status names the tool; thinking tokens are never rendered.
- **No conversation persistence** of any kind: no `localStorage`, no cookie, no server transcript, no
  repeat-question cache (D2), no session id (D1).
- **No multi-session history.** One tab is one conversation, and a reload starts clean.
- **No new colours.** Every addition uses an existing token (`--ui-cite`, `--ui-ink-3`,
  `--ui-ledger-ink`, `--ui-caution`); the warning hue appears once, on web evidence.
