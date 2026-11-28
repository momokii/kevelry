# Changelog

All notable changes to Kevelry (package/image `cve-change-radar`). The public API
is versioned separately at `/api/v1`; every API change in 2.0.0 is additive.

## 4.1.0 — 2026-11-28

Five records asked for one at a time could not finish inside the round cap — three of five read,
the rest silently missing — and a percentage no payload supported printed as though a tool had said
it. A batch lookup, and a numeric check for the figures an answer prints.

### Added

- **`get_cves` reads one to ten ids in a single call.** `get_cve` is one lookup per round, and a round
  is a provider request that the 4-round cap counts. Measured with the fake transport, the same five
  records asked one at a time need 6 rounds — two over the cap — so the turn silently read **3 of 5**
  records and answered from those; one `get_cves` call reads **5 of 5** in a single round. The tool
  returns one entry per id, names ids the dataset does not hold in `missing` (never cited as read),
  and the prompt asks for one batch call when a question needs more than one record. The row-count
  label, per-call citation chips and the tool descriptions follow the same caps the validator
  enforces.
- **Numbers are verified against tool results the way ids are.** The prompt already forbade a figure
  that was not in a tool result, but only ids were checked, so a model could print `99.2%` and the
  desk showed it as though a tool had said it. The prose is now scanned for the shapes a reader would
  act on — percentages, decimals with at least three fractional digits, integers of 1000 or more, and
  ISO dates — and every figure a payload cannot support is reported as printed. A payload's
  `0.99999` verifies `99.999%` but not `99.2%`; ordinals, small counts and bare years are ignored, and
  a turn with no payloads accuses nothing, because with nothing to compare against a figure is
  unchecked rather than doubtful. Unverified figures appear as a quiet caution and in the brief; the
  answer itself is never edited, because the reader is owed the sentence and the doubt.

### Changed (internal)

- **Citations, number checks and web sources live in one pure evidence module.** They were closures
  mutated inside a generator; `src/lib/ai/evidence.ts` now reads a turn's tool outcomes and the prose
  it produced and returns the four lists (cited ids, unverified ids, unverified numbers, web sources)
  with no I/O, no clock and no SSE. The turn module dropped from **819 to 696 lines**, and the rules
  are tested directly instead of only through a provider stream. No behaviour change: zero existing
  tests edited.

**Upgrade notes:** no migration; no API change; no config change. The wire contract at `/api/v1` and
the assistant's request body are unchanged.

## 4.0.9 — 2026-11-28

A refusal that arrived as an error, a "one web fetch per turn" rule that lived only in the prompt,
a money cap that could not trip, and two ends of the wire that disagreed about the caps it enforces.

### Fixed

- **A refusal is an answer, not a fault.** A weaponisation prompt now comes back as a `200` SSE turn
  whose `done` carries `kind: "refusal"`, with two concrete next steps the eight record tools can
  actually answer, and **no provider call** — the 10-prompt fixture asserts zero transport calls. It
  used to render in the error panel, which is where the reader is told something broke: nothing had.
  The copy opens with the same `REFUSAL_TEMPLATE` the prompt gives the model, so a refusal written by
  code and one written by the model read in one voice; a refusal writes no ledger row because it
  costs nothing.
- **"One web fetch per turn" is enforced in code.** It was prompt-only. The tool loop now keeps a
  counter for the turn and refuses a second `fetch_authoritative` call, with a test pinning the
  refusal, so the rule no longer depends on the model remembering it. A successful fetch's citation
  renders as a chip labelled with its host and marked `web`, never `dataset`.
- **A missing gateway `list_cost` no longer records 0.** It did, and a zero is indistinguishable from
  a genuinely free turn, so a gateway that stopped reporting cost made the daily money cap
  unreachable while the provider billed every request. An unpriced turn now records no spend and
  increments `ai_usage.unmetered_requests` (migration 012); after 10 unpriced turns in one UTC day
  the budget fails closed with the honest message — today's AI spend cannot be measured — instead of
  claiming the budget is spent.

### Changed

- **The request-body caps live in one module.** The desk was silently stricter than the server —
  10 messages / 11,000 characters against the route's 12 / 12,000 — so the client trimmed turns the
  server would have accepted, while a client that cannot tell what its server accepts eventually
  builds a body it refuses. Both ends now read `src/lib/ai/limits.ts`, the route keeps its strict
  validation, and the question cap is the per-message cap rather than a fourth number.
- **Duplicate helpers removed.** One `asRecord` (`src/lib/json.ts`), one CVE-id pattern
  (`src/lib/cve-id.ts`), one question cap; two dead exports and two pass-through helpers deleted.

**Upgrade notes:** **migration 012** (`ai_usage.unmetered_requests`) is additive — one column,
default 0, no backfill — and runs automatically on boot against an existing volume. No config change
and no API change: the wire contract at `/api/v1` and the assistant's request body are unchanged, and
a refusal is a `200` the desk labels rather than an error status a client must special-case.

## 4.0.8 — 2026-11-27

A plain question could end with no answer at all: measured **2 of 8** runs of
`Which KEV entries are due in the next 30 days?` settled `done` with an empty
answer — and 3 of 6 attempts while recording the demo. No error, no truncation,
nothing on the stream to say anything had gone wrong.

### Fixed

- **A turn that spends every round asking for tools no longer ends unanswered.**
  The tool-round cap (4) ended the turn the moment `rounds` reached it: the
  settle path emitted `citations` and `done` without ever reading `answerText`,
  then billed the turn as answered. The desk maps `done` to `settled: true`, so
  round-cap exhaustion rendered as a quiet note rather than a fault — a model
  that ran out of rounds read exactly like a model with nothing to say. Both
  empty runs (2 of 8) were still calling tools when the cap fired, and neither
  had a single `finish_reason: length` round, so the token budget was never the
  cause; the retry only ever applied to the first round, because every later
  round already ran at the answer budget.

  Three changes. The **last permitted round is now the answer round**: it is sent
  with `tools: []` and a final-round rule in that round's system prompt, so the
  cap can no longer end a turn that never wrote prose, and a tool call returned
  on it is ignored rather than executed. If that round still yields no text it is
  **retried once** with a compact evidence index — tool name, bounded args, row
  count, up to five ids — instead of the whole transcript: an untrimmed re-send
  was measured at 42.7 s of the 45 s deadline, which turns an empty turn into a
  timeout. And `settle()` **refuses to settle empty**: an empty turn is reported
  as `AI_EMPTY_ANSWER`, a visible fault with its own copy, never a settled
  answer — so a failed turn leaves no brief and nothing in the next request's
  history.

**Upgrade notes:** no migration, no config change — recreate the container to
pick up 4.0.8 (`docker compose up -d --force-recreate`). Round budget and token
limits are unchanged.

## 4.0.7 — 2026-11-26

Three bugs one four-turn session on the shipped 4.0.6 build made visible — a
thumbnail that rendered broken, a `400` on the fourth question, and a turn that
settled empty. All three are client-side. No migration and no config change; the
assistant carries it.

### Fixed

- **The attached thumbnail renders.** The downscaler `fetch`ed its own `data:`
  URL to decode the image, and the page policy keeps `connect-src 'self'`, so
  Chrome refused the connection — twice per attach, four console errors in a
  two-attach session — and the catch fell back to the full payload. The data URL
  is decoded locally now, with no connection for the policy to police, so the
  downscale happens and the thumbnail draws. `img-src` stays
  `'self' data: blob:` and is **not** widened: a unit test pins the exact
  directive (no `*`, no `https:`) and an e2e test pins the header the browser is
  served.
- **A long transcript no longer answers `400`.** The client re-sent the whole
  transcript against the route's 12,000-character cap, so after two or three
  answers the next question was refused. The history is now bounded on the
  client: the newest question is kept whole, the oldest turns are dropped first,
  the suffix stays contiguous and a message is never split — and the turn says
  `Earlier turns were trimmed from context to stay within limits.` when anything
  was dropped. The route keeps its strict validation, and a refusal now names the
  limit it crossed:

  `Message 4 of 12 is 2,431 characters; a single message is limited to 2,000.`

- **A round with neither text nor a tool call is retried once.** It used to
  settle as an empty answer (`The turn ended before it wrote an answer.`). The
  round is re-run once at the answer budget behind the existing `retry` event, so
  the escalation is on the stream rather than silent; a second empty round is an
  `AI_UPSTREAM_ERROR` the reader can see instead of a quietly empty turn. The
  truncated-round retry keeps its one-retry bound and shares the same flag.

**Upgrade notes:** no migration, no config change — recreate the container to
pick up 4.0.7 (`docker compose up -d --force-recreate`). Trimming can drop an
over-long earlier answer: a single message over 2,000 characters is dropped whole
and takes the older turns with it, so a turn that trips the cap carries the newest
question alone and the model may answer from that question without the earlier
context. The turn's note states when that happened.

## 4.0.6 — 2026-11-26

A screenshot is sent with the question that asks for it instead of forever,
turn labels state what happened rather than what is true now, and a turn that
died mid-stream stops claiming it finished. No migration and no config change;
the assistant and the test suite carry it.

### Fixed

- **A screenshot goes with one question, not every question after it.** The send
  condition was "an image exists", so an attached picture rode along on every
  later turn — a plain follow-up about policy shipped 41,538 bytes of image it
  had nothing to do with. Consent is now per question: the image goes with the
  question that attached it, and after that only when that question's own wording
  refers to it (`screenshot`, `this image`, …) or the reader ticks
  `use screenshot in this question`. Measured before and after: the same plain
  follow-up carried 41,538 bytes of image before, zero now.
- **A turn's label states what that turn did.** Labels were derived from live
  state and applied to history, so the moment the payload was cleared, a turn
  whose request _did_ carry the image was told `No longer in context` — a
  statement about the composer, sitting under a turn it was never true of. The
  label is now a fact recorded at send time: `Attached with this question`, or
  nothing at all. Removing the image leaves one note above the composer
  (`Screenshot removed — it will not be sent again.`) and changes nothing already
  said.
- **A failed turn no longer looks finished.** A stream that broke mid-answer kept
  its partial text, offered _Download brief_ and follow-ups, and was replayed to
  the model as history, so a half-sentence read as a whole answer and then sat in
  the context of the next turn. It is now marked incomplete
  (`Incomplete: the answer stopped before it finished.`), excluded from model
  history and the exported brief, and **Retry** continues the attempt that failed
  instead of posting the question a second time.

### Tests

- Four browser journeys close the gaps the audit named: an error mid-stream then
  retry, double-Enter cannot double-send, a refresh mid-stream starts clean, and
  the attach-plus-consent layout at 390px. The suite is 165 e2e tests and 1119
  unit tests (3 skipped, network-gated).

**Upgrade notes:** no migration, no config change. Recreate the container to pick
up 4.0.6 (`docker compose up -d --force-recreate`).

## 4.0.5 — 2026-11-25

The v4 assistant stops looking stopped, says what a screenshot is good for, and
keeps an attached image in the conversation. No migration and no config change;
the image and the test suite carry it.

### Added

- **Assistant progress that visibly moves.** The answer's placeholder is an
  indeterminate 2px sweep, not a computed percentage, and the composer's working
  row names the current lookup in the turn's own words (`reading 25 records…`,
  `writing…`) beside an elapsed counter that ticks four times a second — `0.4s`
  below ten seconds, whole seconds after. The counter is state, so it keeps
  ticking under `prefers-reduced-motion: reduce`, where the bar becomes a static
  hatched track; liveness no longer depends on motion. The form itself carries
  `is-working`, and one `role="status"` region holds the stage, the counter and
  Stop — so a long answer no longer looks stopped.
- **Attachment guidance beside Attach.** A native, keyboard-operable **What
  works** `<details>` names the sources that work — a vendor advisory page with
  CVE ids, an NVD or CVE record page, a scanner report or ticket listing CVEs, a
  PDF page screenshot carrying an id — and the ones that do not: a game
  scoreboard or a photo, a dashboard with no CVE id, vendor or product name. It
  also states that an image with no id is answered as such, which is the desk
  working rather than a failure. `docs/images/attach-example.png` is the pictured
  example, referenced from the README.
- **An attached screenshot stays in the conversation.** The image renders inside
  the question block as a `<details>` thumbnail, expanding in place — the turn
  keeps a ≤480px copy, never the payload. A `screenshot in context · <file> · ×`
  row above the composer re-sends it on every turn while it is there, so
  "explain that screenshot" works on a follow-up. Removing the chip stops it
  being sent and greys every historical thumbnail with a one-line note; the
  privacy line now names the screenshot as well as the transcript.

### Fixed

- **Replay and bench pins no longer rot with the wall clock.** The
  `/api/v1/replay` route has no injectable as-of date and evaluates its 30-day
  retention window against real time, so the benchmark's pinned 2026-10-24
  checkpoint aged into `404 REPLAY_UNAVAILABLE` "expired". The retained-history
  anchor now follows the current UTC day and records it as `radarAnchorDay`; the
  `200` assertion is unchanged.
- **The fake transport concatenates array content.** A user message carrying an
  image is an array of parts, and reading only the string form dropped the
  question — every marker (`as a table`, `with a heading`, the unsupported id)
  died on the turn after an attach. It now joins the `text` parts, so the browser
  suite exercises the journey it names.

**Upgrade notes:** no migration, no config change. Recreate the container to pick
up 4.0.5 (`docker compose up -d --force-recreate`).

## 4.0.4 — 2026-11-23

Four fixes in the v4 assistant, all found on the live 4.0.3 instance. No
migration and no API change; the image and the test suite carry the change.

### Fixed

- **The web fallback now negotiates JSON.** It sent a text-only
  `accept: text/plain, text/html`, so a JSON API answered `406 Not Acceptable` and
  the fallback never returned content at all — NVD API 2.0 did this for both
  `CVE-2099-12345` and `CVE-2021-44228`. The header is now JSON first, then a page,
  then plain text, then anything:

  `application/json, text/html;q=0.9, text/plain;q=0.8, */*;q=0.1`

  A JSON endpoint negotiates, an advisory page still comes back as a page, and an
  unusual content type is readable as a last resort. https, the exact-host
  allow-list, `redirect: manual` with one re-checked hop, the 8 s timeout and the
  256 KB read cap are unchanged.

- **The rail's id sample is 25, the row cap of the common calls.** `search_cves`
  and `list_priority` return at most 25 rows, so a full call reads `25 rows` and
  no longer `25 rows · 12 ids available`, a pair the reader had to decode. A tool
  that really returns more keeps the honest pair: a 50-row `kev_window` reads
  `50 rows · 25 ids available`. Both forms are pinned by tests.
- **The answer's lines keep a word boundary in the text.** A `<br>` is a line
  break in the layout and nothing in `textContent`, so the closing tool line
  arrived glued to the prose — `latest list.Using…` when copied, announced by a
  screen reader, or read out of the DOM. Each line join now emits a collapsible
  space that a line box drops at the break: the render is unchanged and the
  joined string reads `latest list. Using…`.
- **A time-window table has a fixed shape.** KEV entries due and recent additions
  were answered with 4, 2, 3 and 3 columns across four identical questions. The
  prompt now pins `CVE | Date | EPSS`, in that order, on every run.

**Upgrade notes:** no migration, no config change. Recreate the container to pick
up 4.0.4 (`docker compose up -d --force-recreate`).

## 4.0.3 — 2026-11-23

The hardening release for the v4 assistant: the answers read as formatted documents,
the evidence rail fits without its own scrollbar, the page explains itself, and the
guardrails the live 4.0.2 instance exposed now refuse with the right status. No
migration and no `/api/v1` change; two fixes touch the image and the test suite.

### Assistant readability

- **Assistant answers render as structure, not as one block of text.** Pipe tables
  become real `<table>` elements with `<th scope="col">` headers inside a
  horizontally scrollable wrapper, so a wide table scrolls without pushing the page
  sideways. Headings, horizontal rules, blockquotes, ordered and unordered lists,
  bold, italic, inline code and fenced code all render as their elements.
- **A broken marker degrades to the characters the model wrote.** An unterminated
  fence stays literal text — backticks included — until the closing fence arrives,
  so no half-built `<pre>` is ever on screen and a streaming answer agrees with the
  settled one. A lone `**`, a `###` with no text, and `[label](target` with no closing
  paren stay text.
- **Ids link to `/explore` only when the turn's citations named them.** Unchanged from
  4.0.2 and now pinned by a test per construct: prose can never mint a citation the
  tool calls did not return.

### Evidence rail

- **Per call, 6 chips then `+N more`.** Each rail line shows its first six record ids
  and reveals the rest in place; the expanded state is keyed by call, so a later
  delta cannot collapse it.
- **Three calls, then `See all N calls`.** A long transcript no longer becomes a
  scrolling column. `no rows` and `failed` calls are pinned above the disclosure and
  always visible — an empty result is the evidence that a question had no answer.
- **The row labels are honest.** `rows === 0` reads `no rows`, a failed call reads
  `failed`, and a call that returned more rows than ids says so explicitly — a 25-row
  call with a 12-id sample labels itself `25 rows` · `12 ids available`, not `25 rows`
  alone. The row count and the id sample are now visibly different things.
- **"Cited" folds to one line** (`<details>` closed by default at every width) — it is
  the turn's union while the rail is per call, and the summary says which is which.
- **The rail no longer scrolls inside the page.** `max-height` and `overflow` are gone
  at ≥1024px; the ledger stays sticky and its length is content, not a scrollbar.

### Comprehension

- **A legend, a disclosure and five help tips.** The rail opens with one line naming
  what each part is (`Evidence · 4 tool calls`, then rows and chips). A three-sentence
  **How this works** disclosure under the subtitle says where answers come from, that
  every number is quoted from the records the calls returned, and that nothing typed is
  stored. Five `HelpTip`s define `rows`, `tool call`, `cited`, `unverified ids` and
  `session / daily budget` — meaning only, never a file name or an env var.
- **The empty state names its edges.** "Ask about KEV additions, EPSS scores, CVSS, CWE
  or exploit references in this snapshot. It does not forecast, and it will not answer
  from anywhere else."

### Guardrails

- **An oversized body answers `413`, a bad image `422`.** A body over the 3 MB envelope
  used to answer a generic `400`; it now returns `PAYLOAD_TOO_LARGE` with
  `details.maxBytes`. A second image, an image over 1.5 MB, or bytes that are not
  PNG/JPEG/WebP now answer `BAD_IMAGE` with `422`. A malformed body (bad JSON, unknown
  key, too many messages) stays `400 BAD_REQUEST` — those are client bugs, not size or
  content.
- **The burst cap is proven, not assumed.** The reserve is the route's first statement
  and consumes both windows synchronously, so 20 concurrent `POST`s yield exactly 10
  `200` bodies and 10 `429`s; a test asserts it.
- **`AI_MAX_TURNS` is deleted.** It was parsed, asserted in one test, and read by no
  code — a knob no code consumes is a lie with a default. The enforced message cap
  stays 12.
- **The budget is checked before any provider call.** The daily-ledger and session
  tests now also assert the transport spy saw zero calls, so a refusal costs $0.

### Web fallback

- **Machine-readable sources are returned as JSON.** A response whose media type is
  `application/json` or `*+json` comes back as pretty-printed JSON instead of being
  tag-stripped like HTML — the live trigger was a CVE record page that extracted to
  one line of chrome. An HTML page keeps its extraction and now reports its `title`
  plus `mayBeClientRendered`, true when the extracted body is under 200 characters,
  so the model is told the page is a client-rendered shell instead of describing an
  empty one.
- **The prompt names the API before the page:** NVD API 2.0
  (`/rest/json/cves/2.0?cveId=…`), the CISA KEV feed and FIRST EPSS. The tool
  description names both `contentKind` values and the flag.
- **A parity test keeps the prompt and the allowlist together**, so a URL the prompt
  recommends can never be a host the guard refuses.

### Fixed

- **The Docker image installs the glibc Next SWC binding.** `package-lock.json` lists
  both the gnu and the musl variants, and on a glibc base the resolution could land on
  musl alone; Next then loaded no native binding and `next build` aborted. A build step
  asserts the gnu binding, installs it when absent, and hard-fails with the cause when
  it still will not load. This was latent — it only appeared when the dependency layer
  cache was invalidated, so a warm rebuild hid it.
- **Two replay tests no longer rot with the wall clock** (`94a13ab`). The radar and
  replay fixtures derive their dates from a fixed instant instead of "now", so the
  suite passes on any day rather than only inside a retention window.

**Upgrade notes:** no migration, no `/api/v1` change. **`AI_MAX_TURNS` is removed** —
if your `.env` sets it, the value is now ignored and can be deleted. The optional
`AI_MAX_ANSWER_TOKENS` (default `4096`) from 4.0.1 is unchanged. Recreate the container
to pick up 4.0.3 (`docker compose up -d --force-recreate`).

## 4.0.2 — 2026-11-22

Formatted answers. One presentation change, no migration and no API change: an
assistant answer is rendered as text and structure instead of one pre-wrap
paragraph, so a pipe table is a real table and a bullet list is a list.

### Changed

- **Assistant answers are rendered as formatted text.** Pipe tables become real
  `<table>` elements with scoped headers (`<th scope="col">`) inside a
  horizontally scrollable wrapper, so a wide answer table scrolls without
  pushing the page sideways. Unordered and ordered lists, bold, italic, inline
  code, fenced code blocks, and safe links render as their elements; everything
  else stays text.

### Security

- **Output is escaped first and rendered without any HTML injection.** No markup
  string is built from model text and there is no `dangerouslySetInnerHTML`: every
  character of an answer reaches the DOM as a React text child, and the renderer
  only adds structure around it.
- **Links are limited to `https:` and internal paths.** `javascript:`, `data:`,
  protocol-relative (`//host`), scheme-less and plain-`http:` targets render as
  the model's own text and create no anchor; external links open with
  `rel="noopener noreferrer"`.
- **Ids link to `/explore` only when the turn's citations named them.** Prose can
  no longer mint a citation the tool calls did not return.

**Upgrade notes:** no migration, no API change. Recreate the container to pick up
4.0.2 (`docker compose up -d --force-recreate`).

## 4.0.1 — 2026-11-22

The answer-token fix 4.0.0 shipped without. One behaviour change, no migration
and no API change: the round that writes the answer gets a 4096-token budget
instead of the 1024 a tool-discovery round needs, so a table answer is no longer
cut on `finish_reason: "length"`.

### Fixed

- **The final answer round gets `AI_MAX_ANSWER_TOKENS` (default 4096).** 4.0.0
  used one completion cap of 1024 for every round. The first live question
  (`Which KEV entries are due in the next 30 days?`) answers with a table, and
  1024 tokens cut it mid-table as typed `AI_TRUNCATED`. Tool-discovery rounds
  keep 1024 — their completion is a call, not prose — and only the round that
  writes the answer takes the higher budget.
- **An empty truncated round retries once at the answer budget.** When a round
  ends on `length` with no text and no tool calls, the cap was too small for the
  reasoning preamble; it is re-run exactly once at `AI_MAX_ANSWER_TOKENS` and the
  escalation is announced in the stream as a typed `retry` event before the
  second attempt. A round that did produce prose still yields `AI_TRUNCATED`
  rather than a silently short answer, and there is no second retry.
- **The prompt now asks for ≤12 rows plus a remainder count.** When a table
  answers the question, the model lists at most about 12 rows and states the
  total count with how many rows are not shown, so it paces itself instead of
  running into the cap.

**Upgrade notes:** no migration, no API change. New optional env var
`AI_MAX_ANSWER_TOKENS` (default `4096`, floor `512`); leave it unset and the
4096 default applies. Recreate the container to pick up 4.0.1
(`docker compose up -d --force-recreate`).

## 4.0.0 — 2026-11-22

The v4 AI research assistant: a grounded desk over this instance's own corpus,
off by default and outside the versioned read contract. Everything below ships
in this image — the feature is **built and deployed, not enabled by default**,
and it has no effect on an instance that does not set `AI_ENABLED=true`.

### Upgrade notes

- **Migration 011 (`ai_usage`) runs automatically** on the next boot, against an
  existing volume, with no manual step. Additive: one aggregate row per UTC day,
  no backfill, no fact-table change, no read-contract change.
- **The assistant is off unless `AI_ENABLED=true` and a gateway key is present.**
  `AI_API_KEY` is read from the runtime environment only. Without both, the
  `/assistant` page renders the reason and the variable to set; it never renders
  a composer that would fail on submit.
- **`POST /api/assistant/chat` is new but outside the v1 contract.** `/api/v1`
  stays `GET`-only and read-only; no existing endpoint, response shape or status
  code changed. There is no breaking change to upgrade past.
- **Outbound fetch is opt-in.** The `fetch_authoritative` tool is absent from the
  tool list unless `AI_WEB_FETCH_ENABLED=true`, and even then it is limited to an
  allowlist of vulnerability authorities.

### Added

- **Assistant endpoint: `POST /api/assistant/chat`.** Streams SSE
  (`tool`, `delta`, `citations`, `done`, `error`) with `no-store` and
  `X-Accel-Buffering: no`. It sits **outside `/api/v1`** so the versioned public
  contract stays `GET`-only and read-only; the route writes nothing but the
  aggregate spend row. Typed failures: `AI_DISABLED` 503, `AI_BUDGET_EXHAUSTED`
  429, `AI_TIMEOUT` 504, `AI_UPSTREAM_ERROR`/`AI_TRUNCATED` 502, `BAD_IMAGE` 400.
- **A grounded tool layer.** Eight read-only tools — `search_cves`, `get_cve`,
  `epss_history`, `kev_window`, `coverage_stats`, `list_priority`, `cwe_lookup`,
  and the optional `fetch_authoritative` — over the existing loaders, arguments
  validated before any read, every result row- and time-capped. There is no
  shell, filesystem, host, query-language or write capability to reach.
- **Server-derived citations.** The `citations` event is built from the turn's
  own tool results, not parsed from the model's prose; an id the tools did not
  return can never become a link. The **evidence ledger** beside the answer lists
  each tool call with its arguments, row count and returned record ids.
- **Streaming with tool events.** Provider tokens stream through a hand-written
  SSE reader with a session header and an idle timeout; a reasoning model's
  thinking time is shown as named tool activity, never a spinner.
- **Guardrails.** Untrusted tool output is wrapped and labelled as data; a
  pre-inference scope filter refuses the clearest weaponisation, PoC, targeting
  and non-CVE requests at $0; per-IP limits of 10/min and 60/hour with their own
  buckets; a bounded body reader (3 MB, sized for a 1.5 MB image) and a
  2000-character question cap; a 60 000-token session budget and a daily
  `list_cost` budget; `max_tokens` floor 512 with `finish_reason: "length"`
  mapped to `AI_TRUNCATED`, never a short answer. The key is never logged, echoed
  or placed in an error payload.
- **Vision intake.** PNG/JPEG/WebP up to 1.5 MB, magic-byte checked. The prompt
  allows CVE ids read from the image and requires each one to be resolved through
  `get_cve` before it is described; an id that does not resolve is stated as not
  in the dataset. Citations remain server-derived, so an unresolvable id cannot
  become a link.
- **Compare two records.** A disclosure beside the composer sends one fixed
  two-id question and answers it field by field. No fused score, no winner.
- **Brief export.** A completed answer downloads as Markdown with absolute
  citation links and the full tool ledger. Client-side `Blob`; nothing persisted.
- **Entry points.** `Ask` in the rail (`/assistant`), `Ask about this record` on a
  Priority row and the Graph focus (`/assistant?cve=<id>`), and follow-up chips
  derived by code from the turn's ledger.
- **An honest disabled state.** A missing key, an exhausted daily budget or an
  invalid config renders the reason plus the variable to set on `/assistant` —
  never a composer that fails on submit.

### Changed

- **Schema migration 011 `ai_usage`.** One row per UTC day: requests, token
  counts and `list_cost`, so a budget cannot reset on restart. Additive, no
  backfill; no prompt, answer, IP or session is stored.
- **v1 is still `GET`-only.** The new POST is UI-only and unversioned; no
  `/api/v1` route or response shape changed.

### Verified

- `975` unit tests passing with `3` skipped (the network-gated live smokes), and
  `152` Playwright browser tests passing. Lint, typecheck, build and
  `npm audit --omit=dev` (0 vulnerabilities) clean.
  _(Corrected 2026-11-28: the release commit `feae3dd` actually ran **971
  passed / 4 failed** — the four failures were wall-clock fixtures that assumed
  a fixed clock, fixed later in `94a13ab`. The 975 figure was read from a run
  taken after that fix, not from the tagged release. Left in place rather than
  rewritten, because the entry is what was published.)_
- Released as image `kelanach/kevelry:4.0.0` (`latest` points at it) and verified
  live: two real turns on `/assistant` against the gateway, the spend ledger
  written for the day, and `/api/v1/health` reporting schema 11 with four fresh
  sources.

## 3.2.3 — 2026-11-22

Scheduler jitter fix. No migration, no API change, no product surface: the fix is
in how the existing gate decides due-ness and how long it sleeps before the next
look. Deployed and verified against the live `ingest-gate` log.

### Fixed

- **A skipped source is retried within seconds instead of a whole interval.** The
  60 min tick is not exact: on 2026-11-22 the container accepted CVE at
  `07:48:07` (due `08:48:07`) and the tick fired at `08:47:55` — 12 s early — so
  the strict `now >= nextDueAt` comparison called CVE and KEV not due and they
  waited for the next hourly tick. CVE/KEV were effectively polled every ≈2 h,
  repeating every cycle. Two changes fix it:
  - **Grace window.** A source is due when `now >= nextDueAt - 120 s`, capped at
    ¼ of that source's own interval so a short interval keeps its cadence (a
    60 s interval gets 15 s, not 120 s). A tick a few seconds early can no longer
    cost an interval.
  - **Adaptive wake.** The scheduler replaces `setInterval` with a self-rearming
    `setTimeout` that wakes at `min(tick, earliest due)` with a 30 s floor, so a
    source left due in 12 s is picked up in 12 s. Worst-case delay after a skip
    is now ≤30 s. The 60 min tick stays the ceiling, so an idle cycle is still
    cheap. The `ingest-gate` line now reports `nextWakeInMs` — the delay actually
    armed — so this is auditable from logs rather than inferred.

**Upgrade notes:** no migration, no API change. Recreate the container to pick up
3.2.3 (`docker compose up -d --force-recreate`).

## 3.2.2 — 2026-11-22

Scheduling and housekeeping hardening. No product surface, no API contract
change; schema migration 010 widens one CHECK constraint so an abandoned import
can be recorded honestly instead of sitting in `running` forever.

### Changed

- **Each source is polled on its own interval instead of the cycle tick.** CVE and
  KEV run hourly; EPSS and CISA SSVC honour the 24 h interval they always
  declared. `schedule.ts` declared 60 min for CVE/KEV and 24 h for EPSS/SSVC, but
  the cycle ran `Math.min(...)` as its cadence and then attempted all four every
  cycle, so the daily intervals were decorative: EPSS rows were accepted at
  `05:56:57` and `06:57:01` on the same day, i.e. the same CSV re-fetched and
  re-hashed hourly and the 380 MB SSVC checkout fetched hourly with it. Upstream
  fetches fall from ≈96 to ≈50 per day (2 × 24 hourly sources + 2 daily sources).
  A cycle now runs only the sources whose own interval has elapsed and logs one
  `ingest-gate` line naming what ran and why each skipped source was skipped
  (`interval` or `retry`). A skipped source is not a success either: the cycle
  reports which sources it actually attempted, so a day is added to the checkpoint
  history only when an attempted source was accepted.
- **The retry rule keeps the gate from delaying a publication by a day.** An
  attempt that accepted nothing new — today's concrete case is EPSS answering
  403 (or serving yesterday's file) before that day's CSV is published — makes
  the source due again after 60 min instead of after its full interval; only a
  freshly accepted version spends the interval. Without it, a 403 at 05:56 would
  have parked EPSS until the next day, and an unchanged feed would have hidden the
  publication that followed it.
- **The EPSS retention prune is recorded in `maintenance_runs`.** The prune ran
  inside the import and was only logged, so the newest ledger row was
  `exploit-ref-backfill:v2` from 2026-11-08 while rows were being deleted every
  day: "did retention run?" could not be answered from the database. Every prune
  now writes `epss-retention` with `keepDays`, `cutoffDate`, `rowsDeleted` and
  `skipped`, including the run that deleted nothing, and the log line stays.
- **The container log is capped at 10 MiB x 5 files.** `compose.yaml` now sets
  `logging.driver: json-file` with `max-size: 10m` and `max-file: 5`; the default
  `json-file` configuration had no limit, so the log could grow until the disk
  filled. Applying it is a recreate (`docker compose up -d --force-recreate`),
  not a rebuild, and `docker inspect` now reports the limits.
- **Scratch space reclaimed.** A byte-identical DB copy under `/tmp/cvedb`
  (5.6 GB), ~550 Playwright fixture directories under `/tmp/cve-e2e-baseline-*`
  and `/tmp/cve-ssvc-*`, and the benchmark scratch `/data/tmp/bench.db` (156 MB)
  plus a 0-byte `/data/cve-radar.sqlite` in the data volume were deleted after
  checking that no code path references them. The `cve-repo` and
  `vulnrichment-repo` git feeds in `/data` are untouched.
- **The off-site gap is documented, not papered over.** Backups live on the same
  NVMe as the database, so disk loss takes both. `docs/backup-runbook.md` now has
  an "Off-site copy is not included" section with the `rsync -a --delete
~/cve-backups/ user@host:/path/backups/` command an operator can run or cron,
  the note that only the newest verified generation is strictly needed, and the
  reason this repo does not ship replication (no credentials, no provider
  assumptions, operator choice).

### Fixed

- **Abandoned `running` imports are swept at boot.** A process killed mid-import
  never closes its `sync_runs` row, so five rows sat `running` since 2026-11-08
  and a hung import looked exactly like a ledger nobody swept. The worker now
  marks `running` rows older than 2 h `interrupted` before its first cycle —
  never deletes them, never rewrites their timestamps — and `interrupted` is its
  own status so it cannot read as an import failure. Freshness is unaffected by
  construction: the readers pin on `status = 'succeeded'` only.
- **Nightly backups are idempotent and atomic, so a failed generation can be
  re-run.** The script compressed the dump in place with plain `gzip`, which
  refuses to overwrite: re-running a date whose `.gz` already existed died with
  `gzip: ... already exists; not overwritten` after the container had already
  rewritten `cve-backup.db` and `manifest.json`, and because the run aborted
  before its completion marker, every later attempt failed the same way. The
  2026-11-21 generation was left with a 5.42 GiB raw dump and an archive whose
  decompressed SHA-256 (`07e46197…`) did not match the manifest
  (`1b4dd91e…`). The generation is now built in a `.staging-<stamp>-<pid>`
  directory on the same filesystem, compressed with `gzip -f`, verified against
  the manifest with `verifyBackup()`, and only then published with atomic
  renames. A failed or interrupted run leaves the day directory untouched and
  removes its staging tree (EXIT trap), and a non-zero exit is logged with the
  generation name. Today's stamp is always rebuilt, so re-running after a
  failure works and the scheduled run still takes a fresh dump; a past date that
  already verifies is refused unless `--force`, and `--date YYYY-MM-DD` selects
  the date to rebuild (the failure is normally found after the date rolled over).
- **A failed or missing backup is now detected instead of trusted.** The nightly
  script only ever spoke through `backup-cron.log` and a non-zero exit, so a
  night when cron never ran — or 2026-11-21's aborted run — stayed invisible
  until someone read the log a day later. `scripts/backup-check.sh` (cron
  `0 3 * * *`, appending to `~/cve-backups/check.log`) asserts the outcome from
  outside: the newest `backup-done` marker is within 36 h, its archive is
  non-empty and its gzip SHA-256 and byte count match that marker (with a
  `manifest.json` carrying a `dbSha256`; `--deep` also streams `gzip -dc |
sha256sum` against it), no generation holds a raw uncompressed `cve-backup.db`,
  and the newest verified generation is still inside the retention window. One
  timestamped `PASS`/`FAIL` line per assertion plus a verdict, exit `0`/`1`/`2`
  on the same contract as `scripts/health-watch.sh`, no Docker and no network.

### Upgrade notes

- **Includes migration 010.** `010_sync_run_interrupted` widens the
  `sync_runs.status` CHECK to allow `interrupted` (a reversal back to 009 is
  shipped as `010_sync_run_interrupted.down.sql`). It runs automatically on boot
  against the existing volume; there is no manual step and no data rewrite.
- **No API contract change.** Every route under `/api/v1` keeps the shape it had
  in 3.2.1; the 3.2.2 entries are scheduling, ledger, and boot behavior.
- **Freshness semantics are unchanged.** A gated source is not counted as a
  checkpoint success, and readers still pin on `status = 'succeeded'`; the
  aggregate cache version is untouched.
- **The log cap needs a recreate, not a rebuild.** Applying it is
  `docker compose up -d --force-recreate`, which is how this release ships.

## 3.2.1 — 2026-11-22

Performance and cold start. No new product surface, no schema migration, no API
contract change.

### Performance

- **The ranked priority views no longer regroup 10M EPSS rows or sort 410k rows per
  request.** `getHighestForecast` and `getRisingForecast` opened with a
  `GROUP BY cve_id` over the whole `epss_daily` table and joined it back, so every
  request built a temp B-tree over 10,051,241 rows before sorting ~410k
  candidates. The score date's model version is now resolved once (a covering key
  scan, ~53 ms) and joined as `(score_date, model_version)`; a date that mixes
  versions returns null and falls back to the per-CVE regroup verbatim, so ranking
  cannot change. Rising candidates are selected in SQL and only the returned rows
  are hydrated, instead of building four full-corpus maps. Both views read the
  head the aggregate refresh already stores and re-read every displayed value
  live. Measured warm on the live corpus: `?view=highest-forecast` 1.7 s → ~0.14 s,
  `?view=rising-forecast` 2.6 s → ~0.13 s, and the rendered row order is proven
  byte-identical to 3.2.0 by a test that compares the full ordered output of both
  paths.

### Fixed

- **Cold start no longer costs a 20-second first request.** The aggregate read
  model is warmed by the entrypoint (`WARM_AGGREGATES_ONCE=true`, ensure-semantics:
  refresh only when not current) before the port opens, so the first request reads
  the cache instead of falling back to full-corpus live queries under import
  contention. The first response after `up -d --force-recreate` was 20.6 s, now
  ~1.5 s. While that build runs `/api/v1/health` reports `warming` rather than
  publishing stale aggregate numbers.

### Upgrade notes

- **No database migration.** The schema stays at 009; an existing volume needs no
  action and the upgrade is a container replacement.
- **No API contract change.** Every route under `/api/v1` keeps the shape it had in
  3.2.0; the 3.2.1 entries are latency and cold-start behavior.
- **`AGGREGATE_VERSION` is unchanged**, so 3.2.1 does not invalidate the aggregate
  cache on its own. The warm-up at boot is an ensure, not a forced rebuild: a
  current snapshot is left alone.
- **Freshness semantics are unchanged from 3.2.0.** A cached snapshot whose
  revision predates the acceptance ledger is still treated as absent and recomputed
  live; `/api/v1/health` still reports `initializing`, `warming`, or `ok`.

## 3.2.0 — 2026-11-21

The v3 wrap-up: correctness first, then structure and hardening. No new product
surface, no schema migration, no API contract change.

### Fixed

- **A stale aggregate count is never served under a fresh revision.** Every read
  path (overview, status, health, coverage) now checks the aggregate cache against
  the acceptance ledger before trusting it; when the cached snapshot predates the
  accepted source revision, the request falls back to a live query instead of
  pairing new provenance with previous-generation numbers. The cache also stops
  seeding an ETag it cannot vouch for. Covered by a failed-refresh test that
  asserts no response mixes a new revision with old counts.
- **API error responses carry `Cache-Control: no-store`, and no ETag.** A 4xx/5xx
  can now never be memoized by an intermediary for a request that would succeed;
  the documented promise in `docs/DATA_WORKFLOW.md` and `docs/api/README.md` is the
  reason for the header rather than a claim the code did not keep.
- **Expired rate-limit buckets are evicted.** The per-IP map used to grow for the
  life of the process, so a scraped port or an IPv6 /64 churned memory with no
  sweep. Eviction rides an insertion-ordered expiry queue (O(1) amortised, no
  timer), and `docs/api/README.md` now says the 600/minute budget is **per
  process**.
- **The "latest month" stat names the month it measures.** It was the newest month
  _with additions_ labelled as the latest month, so an empty current month made a
  stat and its caption describe different months. It is now "last month with
  additions" with the month named.
- **A missing EPSS observation no longer erases the whole sparkline.** One `null`
  used to collapse the figure to nothing, contradicting `DESIGN.md` §7.0 clause 6.
  The observed points still plot, the line breaks at each gap, and the caption
  states how many observations are absent — a gap is never drawn at zero.
- **Arrow keys wrap at both ends of a roving chart group.** Entering the sparkline
  on the latest mark made the first ArrowRight a no-op; focus and step direction
  now agree, and the wrap is pinned without a DOM.
- **A touch tap pins the KEV rhythm readout.** `pointerup` used to clear the
  tooltip, so the promised "kept until the next tap" did not exist on touch. The
  same pointer-type guard the sparkline already had is applied, and a tap on
  another bar moves the pin.

### Changed

- **One renderer for every chart tooltip and data table.** Seven tooltips
  (`/`, `/explore`, `/priority`, `/graph` surfaces included) and eight data tables
  now render through `ChartTooltip` and `ChartTable`, and the share formatter is
  one helper instead of two precisions. Verified rather than asserted:
  `grep -rn 'className="chart-tooltip\|className="chart-table' src app` matches only
  the primitive files, and the 3.1.0 line claiming the primitives "replace five
  hand-rolled copies" is now true.
- **Donut segments show a visible keyboard focus ring**, matching the graph's rule,
  so a focused segment is distinguishable from hover.
- **Dense chart marks meet the 44px hit-target rule where the layout allows.** The
  accessibility audit now measures focusable `role`-bearing marks, not just form
  controls, and fails on a deliberately undersized one. One measured exception is
  pinned and printed: the KEV rhythm's twelve columns are **23×124** in a 320px
  panel, 1px under WCAG 2.5.8's 24px floor — moving the chart to `span-8` is a page
  composition decision, not a hit-geometry one, and the "All months" table carries
  every value meanwhile.
- **`src/lib` no longer imports out of `app/`.** The CWE display read model moved
  into `src/lib`, so the dependency arrow points the way it should.
- **`OPTIONS` preflights are throttled.** Preflight spends one hit from the same
  per-IP budget (a client can no longer loop them for free) but still takes no
  concurrency slot, because it does no database work. Documented beside the limiter.
- **`CWE_CSV_URL` must be an absolute `https:` URL.** `http:`, `file:`, `data:` and
  relative overrides are refused before any fetch, with the reason logged and the
  pinned MITRE default used instead of throwing.
- **Optional HSTS.** `Strict-Transport-Security` is sent on every HTTPS request;
  `HSTS_ENABLED=true` adds it on plain HTTP too, for deployments behind a TLS
  terminator. Default off, so a direct-HTTP self-host is never bricked.

### Added

- **`CONTEXT.md`** — the domain language this code actually implements: band vs
  cohort, checkpoint vs snapshot, acceptance ledger vs aggregate cache, and the
  narrower-than-common uses of "exploit signal" and "inspectable data".
- **`scripts/nightly-backup.sh --verify <dir>`** re-checks a stored generation with
  the same `verifyBackup()` the nightly run uses (hash, schema, row counts),
  decompressing the gzip into a `mktemp -d` directory that is removed on success
  and on failure. The cron artifact is now verified after compression, so the
  retained gzip passes with no manual `gunzip` step, and the prune refuses a
  backup root that is empty, relative, `/`, or shallower than two path components
  (`exit 2`, before anything is created or mounted).

### Tests

- **632 → 708 unit tests (3 skipped).** The additions cover the chart primitives
  (tooltip shape, clamping and last-30% flip, table structure and empty-series
  copy, roving Arrow/Home/End plus the wrap at both ends), the 44px audit selector
  and its pinned exception, aggregate-currency fallbacks, `no-store` on every error
  status, rate-bucket eviction, the sparkline gap rules, and the https-only CWE URL
  guard.
- **130 → 138 Playwright tests (0 skipped).** The keyboard matrix now covers both
  ends of the roving groups, and the touch-pin journey asserts the KEV tooltip
  survives `pointerup`.

### Upgrade notes

- **No database migration.** The schema stays at 009; an existing volume needs no
  action and the upgrade is a container replacement.
- **No API contract change.** Every route under `/api/v1` keeps the shape it had in
  3.1.0; the 3.2.0 entries are presentation, cache freshness, documentation, and
  hardening.
- **`AGGREGATE_VERSION` is unchanged at 7**, so 3.2.0 does not invalidate the
  aggregate cache on its own. What changes is trust: a cached snapshot whose
  revision predates the acceptance ledger is treated as absent, so the first page
  load after a refresh may compute live counts instead of reading the cache. That
  is expected, not an outage — the cache is rewritten by the next ingest cycle and
  the numbers are equal, only the source differs.
- **`HSTS_ENABLED` defaults off**, so `Strict-Transport-Security` is sent on HTTPS
  requests only. Set `HSTS_ENABLED=true` when the deployment sits behind a TLS
  terminator and every plain-HTTP hop is already redirected.

## 3.1.0 — 2026-11-20

Making every chart value inspectable: a written contract, shared primitives, and the KEV rhythm's twelve months made real.

### Added

- **Inspectable data is a written contract, not a per-chart habit.** `DESIGN.md`
  §7.0 states what "inspectable" means in ten checkable clauses — every mark is a
  hover and keyboard-focus stop, the tooltip has a fixed label / value / share
  shape, a value never exists only on hover, a genuine zero stays a value while a
  missing observation is never plotted as one, and a role follows behaviour. The
  per-chart sections point at it instead of repeating it. The audit and the
  migration phases stay in `docs/plans/data-visibility-standard.md`.
- **`ChartTooltip`, `ChartTable` and `useRovingMarkFocus` replace five
  hand-rolled copies.** `ChartTooltip` renders the fixed shape inside the chart's
  own positioned host, clamps to its edges, flips in the last 30% of the width and
  never covers the mark it describes. `ChartTable` is the `<details>` fallback
  that survives with JavaScript off and states an empty series instead of drawing
  zeros. `useRovingMarkFocus` is the keyboard contract: one Tab stop,
  Arrow/Home/End between marks, real DOM focus so the focused mark's own label is
  the announcement, and Escape for the surface's dismiss.
- **The EPSS sparkline on `/priority` is readable point by point.** One hit band
  per observation maps the pointer to the nearest index, Arrow/Home/End step the
  same series from a single Tab stop, and both show that observation's UTC date,
  probability and model version. The caption prints the observed range and a data
  table lists every observation, so no value needs a pointer.
- **The KEV rhythm on `/` is twelve focusable bars.** Each month gets a
  full-height hit target; hover and keyboard focus produce identical text (full
  month name, `· UTC`, count, and share of the window total); and the window
  maximum is labelled. A month with no additions is drawn as a focusable 1px mark
  reading `0` rather than vanishing — the loaders emit a dense twelve-month UTC
  spine, so a calendar month with no rows is a real zero bucket (see Fixed). The
  panel gains a "How to read" line and a data table, neither of which existed
  before.

### Fixed

- **The KEV rhythm's "twelve months" is twelve calendar months.** `kevByMonth`
  grouped only months that had rows and took the twelve most recent of those, so a
  month with no additions was absent rather than `0`, the window could span more
  than twelve calendar months, and the chart's zero-bar rendering was
  unreachable. Both loaders now build the trailing twelve-month UTC spine
  (`src/lib/kev-months.ts`) and left-join the sparse counts onto it. The caption
  total is the sum of the twelve bars: the real count inside the window. The
  aggregate version goes 6 → 7 so a cached sparse snapshot is recomputed rather
  than served.

### Changed

- **`/graph` links and the severity donut segments are reachable.** Both chart
  roots were `role="img"`, which flattens interactive children out of the
  accessibility tree. The graph root is now a named `role="group"`, so its leaf
  links are reachable again. Each donut segment is now the same real link to the
  severity-filtered Explore view its legend row already was, rather than a
  `role="button"` that did nothing; a band Explore does not accept stays a
  labelled, non-interactive mark.
- **Chart tooltips print full precision.** EPSS is printed from the stored decimal
  string at one fixed three-decimal precision (`54.000%`, not `54%`) at every
  print site — sparkline tooltip, caption range, data table, live announcement and
  the graph badges — instead of passing through a float and trimming trailing
  zeros. The number was never rounded upstream; the loss was in the formatter.
- **The Sankey bands and the Explore cohort months no longer lean on a native
  `title`.** Each is a real mark carrying the shared tooltip, or printed text
  where the value was already on screen.

### Removed

- **`charts/SeverityMix`.** Nothing imported it: no route and no test, and the
  overview had already moved to the severity donut. Its P4 migration is superseded
  by removing the component rather than maintaining an unmounted copy of the
  pattern.

### Tests

- **622 → 632 unit tests (3 skipped).** The seven EPSS-precision cases pin
  `displayProbabilityPercentFixed` and `formatEpssPercent` so a formatter change
  cannot silently re-round a published probability; three more pin the dense KEV
  month spine (twelve buckets, zeros in the gaps, window-bounded sum) in both the
  cached and live loaders. The Playwright suite gains one gap-month KEV rhythm
  assertion (129 → 130 passed / 0 skipped).

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- `AGGREGATE_VERSION` moves 6 → 7, so the aggregate cache is rebuilt on the first
  boot after the upgrade. That is expected and needs no action.
- No API contract change: every 3.1.0 entry is presentation, documentation, or an
  internal cache version.
- The KEV rhythm now always shows twelve calendar months, including zero months,
  so a month that previously vanished from the chart now appears as `0`.

## 3.0.2 — 2026-11-17

### Fixed

- **The `/graph` attribute dialog ignored Escape once the filter had focus.** The
  filter is a `type="search"` input, so the browser consumed the first Escape to
  clear the field itself: the dialog never received `cancel` and stayed open. The
  input now clears the filter and closes the dialog on the first Escape, without
  `preventDefault`, so the native close path still runs. Covered by an
  unconditional regression test that arms the swallowed-Escape path, then asserts
  the dialog closed and the filter was dropped for the next open.

### Changed (tests only)

- **The e2e suite runs against its own fixture corpus.** `global-setup` seeds
  `.e2e/data` and `global-teardown` removes it, and the Playwright dev server
  starts with `DATA_DIR=./.e2e/data`, `SCHEDULE_ENABLED=false` and
  `INGEST_ON_START=false`. The suite no longer reads or writes the checkout's
  `data/cve.db`, so a spec that swaps its corpus cannot disturb a running
  instance, and full-suite counts are deterministic: 129 passed / 0 skipped,
  with no guard left to skip. The `+N more` journey now deploys a dense cohort
  so the attribute group clears the drawing cap. No runtime change.

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- No API contract change: the fix is a client-side key handler.
- No config change: the Compose environment contract and `/data` layout are
  unchanged.

## 3.0.1 — 2026-11-17

### Security

- **Next.js 16.4.3 → 16.4.5** for CVE-2026-119348 (GHSA-pc58-hwjq-p385).
  `npm audit --omit=dev` is clean.

### Added

- **Atom 1.0 change feed** at `GET /api/v1/radar/feed.atom`, conforming to
  RFC 4287 and built from the same retained checkpoints as the RSS feed.
- **CWE names in the relation graph.** The graph payload now carries
  `cweDetails` plus the `cweCatalog` envelope, so shared-CWE groups, hub chips,
  and drill-down labels read `CWE-416 · Use After Free`.

### Fixed

- **CWE phase markers leaking into payloads, then mitigations parsing to
  empty.** The importer strips marker runs before the 600-code-point cap, and
  the read path parses `::PHASE:`/`:DESCRIPTION:` segments instead of deleting
  `::…::` pairs. Across the 692 stored mitigations this took empty results from
  333 to 0 and left 692 non-empty, with no `::PHASE` or `PHASE:` text in any
  payload.

### Changed

- **One `withApiRoute` wrapper** now serves all 14 API routes, replacing the
  repeated guard sequence; duplicated display and feed helpers are
  consolidated, and the v3 files are formatted with Prettier.

### Upgrade notes

- No migration: the schema stays at 009 and existing volumes need no action.
- No API contract change: every 3.0.1 addition is additive, and the wrapper is
  structural only.

## 3.0.0 — 2026-11-15

All five v3 epics are implemented, verified, and shipped in this release.

### Added

- **CWE names in the relation graph (E3).** The graph payload now carries the
  additive `cweDetails` (keyed by normalized `CWE-<n>`, covering every id the
  cohort references) plus the `cweCatalog` envelope, resolved in one batched
  catalog lookup per response, and the shared-CWE group labels, hub attribute
  chips, drill-down title and data table render `CWE-416 · Use After Free` with
  the canonical MITRE link, `not in the loaded catalog` for an unmapped id, and
  one block-level `taxonomy unavailable` note when no catalog is loaded.

- **CWE chips, states, and mitigation disclosure in the Priority view (E3 step
  3b).** The expanded Priority row now renders every `kev.cweDetails` ref from
  the API instead of the raw id strings: the mono id is the label, and a
  `known` id joins it with the published catalog name at a bounded width
  (`CWE-79 · Improper Neutralization of Input During Web Page Generation …`).
  The id never truncates, is never replaced by the name, and is never hidden.
  The whole chip is one link to the canonical
  `https://cwe.mitre.org/data/definitions/<n>.html` (`target="_blank"`,
  `rel="noreferrer noopener"`), with a 44px target and a visible keyboard focus
  ring; `unmapped` chips add the words **not in the loaded catalog**, and
  `taxonomy-unavailable` says **taxonomy unavailable** once at block level so
  each id still renders as its own chip. No severity colour, no band class, and
  no "vulnerable to" phrasing: an id names a weakness class, not a confirmed
  exploit. `known` ids that published mitigation text gain a `<details>`
  disclosure labelled `Mitigation (reference, MITRE CWE <version>)`, with the
  version read from a new additive `cweCatalog` envelope block
  (`{status, version, retrievedAt, source}` on the detail and priority
  responses) rather than hard-coded, the already-stripped body text, and a
  `HelpTip` stating it is published guidance whose applicability depends on the
  product. The page resolves every rendered row's ids in one batched catalog
  lookup; the component stays presentational. Docs: `DESIGN.md` (chip anatomy,
  the three states, disclosure contract), `docs/DATA_WORKFLOW.md` (catalog
  provenance and the version-label rule), `openapi/v1.yaml` (`CweCatalog`),
  `docs/api/cves.md`, `docs/api/priority-lists.md`, and `.env.example` /
  `README.md` now describe `CWE_REFRESH_ENABLED` as **fail-closed** for config
  parsing (fetch failure remains fail-soft/last-known-good). Tests:
  `tests/priority-view.test.ts` covers the chip/name and disclosure-label
  helpers; `tests/api-routes.test.ts` covers the `cweCatalog` envelope;
  `tests/e2e/priority-cwe.spec.ts` covers a known chip's id, name, canonical
  href and `rel`, an unmapped id, a single block-level `taxonomy unavailable`
  with an empty catalog, the keyboard-opened disclosure (no `::`, names the
  version, HelpTip present), and 360px/dark-theme readability asserted through
  computed colours.

- **CWE labels in API payloads with marker stripping and a fail-closed flag
  (E3 step 3a).** `GET /api/v1/cves/{cveId}` now serves a top-level
  `cweDetails: CweRef[]` alongside `kev.cwes` (same order, deduped after
  normalization, never omitted), and every priority row carries the additive
  `kev.cweDetails`, resolved for the whole page in one batched catalog lookup.
  `CweRef.status` keeps the three states distinct — `known` (published `name`
  plus `abstraction`/`summary`/`mitigation` only when MITRE published them),
  `unmapped`, and `taxonomy-unavailable` (still present, with its canonical
  `url`) — so an absent or stale catalog never removes an id and never invents a
  name. List, search, and bulk rows stay ID-only by design. A new
  `stripCweMarkers` in `src/lib/cwe-catalog.ts` removes MITRE's `::PHASE:…::`
  control markers (plus any other `::…::` run), collapses whitespace, and never
  throws; it runs at projection time only, so stored rows stay verbatim and no
  payload contains `::`. `CWE_REFRESH_ENABLED` is now **fail-closed**: only
  `true`/`false` are accepted, absent still means enabled (the job is 24 h-gated
  and hash-conditional), and any other value disables the refresh and logs one
  `cwe-refresh-config-invalid` event with the value sanitised to a single,
  length-capped line — a typo can no longer look like consent to fetch
  upstream. Docs: `openapi/v1.yaml` (`CweRef`, detail `cweDetails`, priority
  `kev.cweDetails`), `docs/api/cves.md`, `docs/api/priority-lists.md`,
  `DESIGN.md` (chip anatomy, marker rule, list rows stay ID-only), and
  `docs/DATA_WORKFLOW.md` (payload states, fail-closed flag).

- **CWE catalog ingest with last-known-good (E3 step 2b).**
  `refreshCweCatalog(db, options)` in `src/lib/cwe-import.ts` is now the only
  writer of `cwe_entries` / `cwe_catalog_meta`: fetch → `extractSingleEntryZip`
  → `parseCsvRows` → `mapCweCsv` → one transaction. The pin is MITRE's
  “Research Concepts” view, `https://cwe.mitre.org/data/csv/1000.csv.zip`
  (verified 2026-11-14: HTTP 200, `application/zip`, 644,612 bytes, one 3.2 MB
  CSV, 956 accepted entries); `CWE_CSV_URL` may override it but must be an
  absolute https URL. Caps: **8 MiB** downloaded zip, **64 MiB** extracted CSV
  entry, **16 MiB** parsed CSV text, **30 s** fetch timeout, **300 chars** per
  stored reason. `version` is `<view id>-<entry count>` (`1000-956`) because the
  published CSV carries no version marker; `source_hash` (SHA-256 of the
  accepted zip bytes) is the exact pin. Acquisition is **conditional**: when the
  downloaded bytes hash to the accepted `source_hash` nothing is parsed and
  nothing is written (`{ status: "unchanged" }`), and a hash match on a
  non-`ready` row whose entries are intact restores `ready` without re-parsing.
  **Publication is one transaction** (`DELETE` + inserts + meta upsert), so a
  reader never sees a half-replaced taxonomy and a failure mid-publish rolls
  back. Failure is **last-known-good**: entries are never deleted, the meta row
  records `status='stale'` with a sanitised `notes` reason (single line,
  credentials stripped, ≤300 chars), and the call returns
  `{ status: "failed", reason }` instead of throwing. The worker hooks this as
  maintenance that is _not_ a scheduler source (it cannot contribute to
  `failed`/readiness or block an import): at most one attempt per 24 h, gated by
  the accepted `retrieved_at` and tracked in-process, awaited once at boot and
  fired after each settled cycle, logging `cwe-refresh`,
  `cwe-refresh-unchanged`, or `cwe-refresh-failed`. `CWE_REFRESH_ENABLED=false`
  disables it and `REFRESH_CWE_ONCE=true node dist/worker.mjs` performs exactly
  one attempt (exit 1 on failure) for seeding or retrying a stale catalog.
  `tests/cwe-import.test.ts` drives everything through injected fetchers — no
  network — covering publish, the unchanged no-write path, HTTP 500, timeout,
  bad zip, oversize payload, mid-publish rollback, stale recovery, the
  https-only URL rule, reason sanitisation, the cadence gate, and the one-shot
  path; `tests/setup.ts` pins `CWE_REFRESH_ENABLED=false` so no test boot reaches
  upstream. Source terms, the verified URL, and the safety properties are
  documented in `docs/research/SOURCES.md`; cadence and failure semantics in
  `docs/DATA_WORKFLOW.md`.

- **Dependency-free CWE zip reader and CSV mapping (E3 step 2a).**
  `src/lib/zip.ts` reads a single-entry MITRE `CSV.zip` using only
  `node:zlib`: End of Central Directory, the central-directory record, then the
  one local header; stored (0) and deflate (8) are supported, sizes come from
  the central directory, and rejections are typed `ZipExtractError`s
  (`not-zip`, `entry-count`, `encrypted`, `unsupported-method`, `multi-disk`,
  `zip64`, `declared-size`, `inflated-size`, `corrupt`) instead of raw Node
  errors. The required `maxUncompressedBytes` cap is enforced against the
  declared size and passed to `inflateRawSync` as `maxOutputLength`, so a zip
  bomb is stopped before it allocates. `src/lib/cwe-import.ts` adds a bounded
  RFC 4180 reader (`parseCsvRows`, 16 MiB cap; quoted fields, embedded commas
  and line breaks, doubled quotes, CRLF/LF, no final newline) and `mapCweCsv`,
  which maps by header name (`cwe-id`/`id`, `name`, `abstraction`, `status`,
  `description`, `mitigation`), ignores unknown columns, normalizes ids through
  `normalizeCweId`, skips and counts rows with an unusable id, blank name, or
  duplicate id, strips CR/LF to spaces, and truncates summary/mitigation at 600
  code points with `…`. No fetch, worker wiring, UI, or database write in this
  step. Tests in `tests/cwe-import.test.ts` build zip fixtures in-process
  (stored, deflated, multi-entry, encrypted, declared-size, bomb) and cover CSV
  quoting, CRLF/LF, header reordering, unknown columns, skipped ids, and
  truncation.

- **Local CWE taxonomy schema and reader (E3 step 1).** Migration 009 adds two
  additive tables: `cwe_catalog_meta` (a pinned one-row pointer to the accepted
  catalog with `version`, `source`, `source_hash`, `retrieved_at`, `status`,
  `record_count`, and `notes`) and `cwe_entries` (normalized `CWE-<n>` primary
  key with `name`, optional `abstraction`/`status`/`summary`/`mitigation`,
  `version`, `updated_at`). No fact table changes and no extra index beyond the
  entry primary key. `src/lib/cwe-catalog.ts` is the purely local read seam:
  `getCweCatalogMeta` reports `ready`, `stale`, `unavailable`, or `empty`, and
  `resolveCweIds` maps caller ids to a `CweRef` in one of three states —
  `known` (with the published fields and canonical MITRE URL), `unmapped`
  (valid-shaped id absent from the catalog, or an unparseable input retained as
  its raw string), or `taxonomy-unavailable` (no accepted catalog, so no name
  is claimed). `CWE-79`, `cwe-79`, and `79` normalize to `CWE-79`; inputs are
  deduped and looked up in bounded `IN` batches. The reader never throws on
  caller input, never fabricates a label, and never touches upstream. Tests in
  `tests/cwe-catalog.test.ts` cover known/unmapped/unavailable resolution,
  absent mitigation, normalization, dedupe, invalid shapes, chunk boundaries,
  and the `empty` meta state before any load.

- **Page-bounded CSV/JSON export and subscribe controls (E5).**
  `GET /api/v1/search` now accepts `format=csv|json` and serializes **exactly
  the page it already returned** — the same validation, filters, ordering,
  `limit`, and `cursor`, with no fan-out and no second scan. `format=csv` answers
  `text/csv; charset=utf-8` with `Content-Disposition: attachment;
filename="kevelry-search-<UTC date>-<n>rows.csv"` and the stable column order
  `cveId,title,state,publishedAt,updatedAt,severityBand,primaryCvssVersion,
primaryCvssScore,kevListed,kevDateAdded,epssValue,epssPercentile,
exploitTagged,officialUrl`, RFC 4180 quoting (comma, quote, CR, LF; embedded
  quotes doubled), null/absent values as empty cells, and **no `#` comment
  rows** — the file is a header row plus data rows only, because spreadsheet and
  SQL importers would read comment rows as data. `format=json` is the unchanged
  envelope (`q`, `vendor`, `data`, `pagination`, `coverage`, `provenance`) plus
  the attachment headers; an absent `format` keeps today's JSON response and an
  unknown value is `400 BAD_FILTER`. Exports share the JSON routes' ETag/304 and
  cache policy. Explore's results header adds `Export CSV` / `Export JSON`
  controls labelled with the page's row count (`Export CSV (20 rows)`), 44px
  targets that link to `/api/v1/search` with the current query string, cursor,
  and page `limit`; they are disabled with a visible explanation only when the
  page genuinely has no rows. Export mode is the one documented exception to the
  `q`/`vendor` requirement, so the default unfiltered Explore view is
  exportable: `format=csv|json` without either serializes the same unfiltered
  first page (same ordering and bounds), while a plain JSON request without
  `format` still answers `400 BAD_QUERY` and the error message states the
  exception. The Radar view adds a `Subscribe` block: a 44px
  link to `/api/v1/radar/feed.xml` with the RSS type plus a read-only URL field
  that selects itself on focus, so the feed URL is copy-able by keyboard. Docs
  updated in `docs/api/search.md`, `docs/api/radar.md`, `openapi/v1.yaml`, and
  `DESIGN.md`; tests cover quoting, the column/header contract, `limit`-bounded
  rows, filter parity with JSON (an `exploit=tagged` export cannot leak the
  unfiltered set), row-set parity between the page's own query path and the
  unfiltered export, the invalid-format error, and the controls at 360px.

- **RSS 2.0 change feed (E5).** `GET /api/v1/radar/feed.xml` serializes the
  events `GET /api/v1/radar` already serves from retained checkpoints, for
  anonymous pull subscribers. It reuses the JSON route's parsers and filters:
  `since` (UTC `YYYY-MM-DD`), `kind`, `cveId`, and `limit` (default 50, max 200);
  invalid values return the same `BAD_FILTER`/`BAD_LIMIT` codes. `since` older
  than the 30-day checkpoint retention window is `400 BAD_FILTER` naming the
  earliest allowed date — never an empty 200 that would read as "no changes".
  Items are factual only: `<guid isPermaLink="false">` is the `eventId`,
  `<title>` is `<cveId> — <kind>`, `<pubDate>` is the RFC 822 form of
  `observedAt`, `<link>` is the canonical cve.org record, and `<description>`
  lists `field: before → after` lines then `reason:` then `sourceRevision:`,
  XML-escaped (`&`, `<`, `>`). The channel names accepted local snapshots and
  the retention window and sets `<lastBuildDate>` from the newest checkpoint.
  Success responses use `Content-Type: application/rss+xml; charset=utf-8`,
  `Cache-Control`, and a strong `ETag` seeded from the retained checkpoint set
  (newest date, oldest date, count) plus the validated query shape, so a repeat
  request revalidates as `304`. The feed uses the shared rate-limit,
  concurrency, request-bound, preflight, and security-header guards; errors
  stay JSON. Docs updated in `docs/api/radar.md`, `docs/api/README.md`, and
  `openapi/v1.yaml`. Export, UI subscribe controls, and Playwright remain out
  of scope for this API-only step.

- **Atom 1.0 change feed (E5).** `GET /api/v1/radar/feed.atom` serializes the
  same retained change events as the RSS feed into an RFC 4287 document for
  subscribers that prefer Atom. It shares the RSS route's query parsers, 30-day
  retention clamp, event selection and ordering, ETag seed, conditional `304`,
  cache policy, and guardrails; only the serializer, content type
  (`application/atom+xml; charset=utf-8`), feed path, and ETag discriminator
  differ. Feed `id`, `title`, `updated`, and `author/name` satisfy RFC 4287
  §4.1.1, entries carry `id` (the same `eventId` as the RSS `<guid>`), `title`,
  RFC 3339 `updated` (§3.3), `summary`, and an alternate cve.org link (§4.1.2),
  and `rel="self"` / `rel="alternate"` are omitted when the public origin is
  unknown, exactly like RSS. Docs: `docs/research/atom-feed.md`,
  `docs/api/radar.md`, `openapi/v1.yaml`, README, and the Radar subscribe
  control now offering both formats at 44px with the retention note. Tests:
  `tests/radar-feed.test.ts` (well-formedness, required elements, cross-format
  id equality, RFC 3339 dates, escaping, retention `400`, `304`) and
  `tests/e2e/radar.spec.ts` (both links and both routes at 360px).

- **Daily checkpoint writer (E5).** The worker now actually fills the
  `checkpoints` table the Change Radar, replay, and RSS feed read. After every
  ingestion cycle in which at least one source was accepted it freezes exactly
  one checkpoint for the current UTC date; a second cycle on that date writes
  none (checkpoints stay immutable), and a cycle where every source failed
  writes none. Source pins are the accepted versions already recorded in
  `sync_runs` (last succeeded run per source; for KEV the observed catalog date
  the accepted catalog wrote), the policy version is `RADAR_POLICY_VERSION`,
  and the per-view cap is the validated `CHECKPOINT_TOP_N` resolver, so the
  daily write stays bounded. The write is fail-soft: a missing accepted pin, a
  rejected bound, or a store error logs `checkpoint-write-failed` and the cycle
  still completes, so a checkpoint fault can never fail an import or block the
  next source. With no retained checkpoint the RSS channel `<description>` now
  states "No change checkpoints are retained yet; this feed fills as the daily
  checkpoint writer runs." instead of leaving an empty item list to read as
  "no changes"; the response stays `200` with a valid empty channel. Tests
  cover one write per UTC date, the repeat-cycle no-op, the all-failed cycle, a
  logged write failure, and the empty-feed wording.

- **Bulk CVE lookup route (E4).** `GET /api/v1/cves/batch?ids=CVE-…,CVE-…`
  returns up to 50 records in one bounded read. `ids` is required, trimmed,
  empties dropped, and deduped preserving first-seen order, so `data` is in
  requested order; every element must match `CVE-YYYY-NNNN+` and the cap is 50
  unique IDs. The envelope is `{ data, resolution: { requested, returned,
missingIds }, provenance }`: absent and not-publicly-visible IDs are listed
  in `resolution.missingIds` (requested order) instead of being fabricated or
  failing the whole request with a `404`. The route deliberately does **not**
  reuse the list route's `coverage` key, which keeps its single meaning
  (eligible cohort). Known list/search params (`cursor`, `limit`, `severity`,
  `kev`, `epss`, `exploit`, `publishedStart`, `publishedEnd`, `vendor`, `q`)
  are rejected with `400 BAD_REQUEST` naming the param; any other unknown
  parameter is ignored. Success responses carry the usual strong `ETag` seeded
  over the canonical sorted ID set plus the aggregate revision, so the same set
  in any order revalidates as `304`. Guardrails are the shared ones (`getDb`,
  rate limit, concurrency slot, request bounds, `preflightResponse`), and items
  are exactly the `CveItem` shape the list route serves, so a bulk item
  deep-equals the same record from `GET /api/v1/cves/{cveId}` minus the
  detail-only extras. `BAD_ID` joins the error catalog. Docs updated in
  `docs/api/cves.md`, `docs/api/README.md`, `openapi/v1.yaml`, and the
  `/api-docs` page. Playwright is out of scope for this API-only epic.

- **Unscored coverage counters and the secondary coverage detail block (E1).**
  `unscored` was one number for two different situations. The aggregate cache
  now splits it with two additive SQL counters over the same predicates the
  severity bands already use (never `raw_json`): `secondaryOnly` (PUBLISHED,
  no valid CNA metric, at least one valid ADP metric — context exists) and
  `noMetric` (no valid CNA and no valid ADP metric — nothing published). They
  are an exact partition of the unscored cohort, asserted in
  `tests/aggregates-coverage.test.ts`, and `AGGREGATE_VERSION` moves to 6 so an
  older snapshot is rejected instead of read with missing keys.
  `/api/v1/overview` exposes both in its `coverage` block; every existing field
  keeps its name and meaning (list endpoints are unchanged). The overview's
  "Unscored severity" stat gains the subnote `X with ADP secondary (context) ·
Y with no published metric` with the unscored cohort as denominator and a
  `HelpTip` stating secondary is context only and never used for ranking or
  eligibility — no band colour, no filter. The expanded Priority severity block
  gains a "Secondary (context only)" group listing each metric's origin/
  provider, version, base score, and vector, or the explicit line "No CNA or
  ADP metric published." Secondary never renders as a band, never appears in
  the compact signal line, and is never filterable. The api-docs CVE detail
  example now includes `cvssSecondary`, closing the drift left by the previous
  entry. Playwright covers the subnote numbers at 1280/360px and in dark theme,
  plus the detail block (words "context only", no `badge-*`/band class, absent
  from the compact signal line).

- **KEV ransomware tri-state and self-describing block (E2).**
  `kev_entries.ransomware_known` is an integer, and its three states now have
  one documented mapping (`kevRansomwareUseOf` in
  `app/api/v1/_lib/records.ts`): `1` → `"known"`, `0` → `"unknown"` (the
  catalog's own Unknown value), `NULL` → `"unstated"`. `0` and `NULL` are never
  collapsed, and no output renders a ransomware-free claim from either. Every
  `CveItem.kev` block gains `ransomwareUse` additively and keeps
  `ransomwareKnown` as a legacy boolean alias (`true`/`false`/`null`) so
  existing consumers are untouched. The block is self-describing: `listed`,
  `dateAdded`, `dueDate`, `requiredAction`, `vulnerabilityName`, `cwes`, with
  absent catalog text served as `null` (never `""`) and empty `cwes` as `[]`.
  OpenAPI, `docs/api/cves.md`, and `docs/DATA_WORKFLOW.md` document the mapping
  and that KEV dates/text are catalog facts, not first-exploit time or a
  universal SLA. `tests/kev-ransomware.test.ts` pins the 1/0/NULL matrix, the
  legacy alias, the all-missing null shape, and the absence of negated
  ransomware wording.

- **KEV block labels, tri-state copy, and Playwright coverage (E2).** The
  expanded Priority row's KEV block renders a labeled row per catalog fact
  instead of one sentence: membership `Listed` / `Not listed`, `Date added
(catalog)`, `Due date (catalog, federal context)`, `Required action`
  (catalog-supplied and wrapped), `Ransomware campaign use`, `Catalog name`, and
  `CWEs` as monospace ID chips. The block branches on `ransomwareUse`, so the
  three catalog states render distinctly — `Known (catalog)`, `Unknown
(catalog)` (the catalog's own value), `Not stated` (the field was absent) —
  and the legacy `ransomwareKnown` boolean is no longer read by the UI. No state
  is negated: "no ransomware", "not ransomware", and "no known ransomware"
  never render. Absent fields say `Not provided` (never blank), the block's
  HelpTip states that KEV is catalog membership evidence rather than
  first-exploitation time or a universal SLA, and the block holds at 360px/200%
  in both themes with a 44px keyboard-reachable HelpTip. Playwright seeds
  known/unknown/unstated KEV rows and pins the exact labels, the banned phrases,
  the focus-only HelpTip path, and the narrow dark layout.

- **Secondary CVSS projection (`cvssSecondary`).** Every preserved metric the
  primary selector did not pick is now exposed on `CveItem` as one bounded,
  labeled block instead of being dropped. The projection hides the shape
  decisions behind a single pure function (`src/lib/cvss-projection.ts`): it
  excludes the metric `cvssPrimary` selected, orders the rest ADP before CNA,
  then version preference 4.0 > 3.1 > 3.0 > 2.0, then base score descending on
  exact decimal text, then stored source order; it caps the block at four
  metrics, skips malformed scores instead of rendering them, and labels every
  entry `secondary (context only)`. `coverageNote` states in prose that the
  metrics are not used for ranking or eligibility. **Ranking and eligibility are
  untouched**: severity bands, ordering, filters, and the new-critical cohort
  still read the primary selection alone, and `cvssPrimary` keeps its exact
  previous shape. `hasAdp` stays on the record as a compatibility alias.
  Tests cover the ADP-only, CNA+ADP (primary excluded), multi-ADP ordering and
  cap, legacy-only, none, malformed-value, and determinism cases, plus an API
  shape assertion that `cvssSecondary` is additive and `cvssPrimary` unchanged.

### Documentation

- Reconciled the standards, the API docs, and the v3 plan with shipped behaviour: the `app/api/v1/_lib/shared.ts` split, the CWE ingest's own `parseCsvRows` (not `parseEpssCsv`), `hasAdp` kept as a deprecated alias, the `cvssSecondary` scope, and export-mode `q`/`vendor`. No behaviour change.

### Upgrade notes

- **Migration 009 applies on the next write open** of the database (the first
  boot or cycle after upgrading). There is no manual migration step and no
  downtime beyond a normal restart.
- **The aggregate cache version is now v6**, so the first cycle after upgrading
  performs one full refresh. Expect one slower first render; later page loads
  use the refreshed cached snapshot as before.
- **The CWE catalog is fetched once on the first cycle** — a ~644 KB download of
  the pinned MITRE `1000.csv.zip` — and is hash-conditional afterwards (one
  conditional request per 24 h). `CWE_REFRESH_ENABLED=false` skips the fetch, and
  the UI stays readable with ids only.
- **The checkpoint writer starts producing one row per UTC date**, so Change
  Radar, Replay, and the feed have no history before the first day of running
  3.0.0. History accumulates from that date forward.

## 2.0.2 — 2026-11-11

Two operational bugs found while verifying the 2.0.1 release on a running
instance. Both made the console degrade silently rather than fail loudly.

### Fixed

- **Scheduled cycles never refreshed the aggregate cache.** Only the boot cycle
  called the refresh, so after the first hourly cycle the cached snapshot no
  longer matched the accepted data; pages rejected it and every overview render
  fell back to live full-corpus queries (4.3 s instead of 0.28 s) until the next
  restart. The scheduler now reports every settled cycle through
  `onCycleComplete`, and the worker refreshes from there — including cycles where
  one source failed, because the sources that succeeded still moved the data.
- **The cache freshness check compared the wrong revision.** It used
  `MAX(source_revision)` over `cve_records`, which is a lexicographic coincidence
  after an incremental import (only touched rows carry the new revision), and the
  snapshot had the same flaw. Both now use the acceptance ledger (`sync_runs`),
  and the snapshot records the accepted CVE revision, KEV version, SSVC revision
  and EPSS score date. Aggregate cache version 5.
- **A stale `git` lock could freeze the CVE feed indefinitely.** A process killed
  mid-fetch (deploy, OOM) leaves `.git/*.lock` behind and every later fetch fails
  with "Another git process seems to be running". The importer now clears locks
  older than the fetch timeout before retrying, and reports it
  (`cve-cache-lock-cleared`). This is what left the corpus frozen for a day on
  2026-11-10.

### Notes

- The instance that exposed these had been running since 2.0.1: 402k → 405k
  records were waiting in the fetched git cache while the feed reported failures.

## 2.0.1 — 2026-11-08

Storage and operations follow-up to 2.0.0, plus the fixes found while rehearsing
the release.

### Changed

- **EPSS history is ~40% smaller and the window is a stated budget.** Migration
  008 rebuilds `epss_daily` as `WITHOUT ROWID` with the primary key ordered
  `(score_date, cve_id, model_version)`, so the clustered key replaces the
  separate covering index. Measured on the production data: 935 MB → 599 MB
  (62.3 → 39.9 MB per day), with identical query plans.
- **`EPSS_RETENTION_DAYS` default 90 → 45** (and the per-record history cap
  moves with it). Six weeks of trend with a month of margin over what the
  sparkline and the 7-day rising delta need; ~1.8 GB instead of ~5.6 GB.
- The methodology page, the environment reference and the backup runbook state
  the new arithmetic.

### Fixed

- The restore drill is now a documented command (`RUN_RESTORE_ONCE`,
  `RESTORE_DIR`) and was rehearsed end to end: a 639 MB verified backup restored
  into a throwaway volume (402,045 records, 5.6M EPSS rows), served every page,
  and `/api/v1/health` reported all four sources current.
- Nonce-based CSP for page HTML (from the 2.0.0 audit), with the watch-list write
  moved out of a React state updater so unwatching no longer restores the old
  list.

### Upgrade notes

- Migration 008 rebuilds the EPSS table once on the first write open (~20-30 s
  for 6M rows on the reference host). The file does not shrink; freed pages are
  reused by later imports, which is what keeps the steady state at ~40 MB/day.
- Nothing else changes shape: no API, no query, no ranking behaviour.

## 2.0.0 — 2026-11-08

Second product release. Four new evidence surfaces, a fourth upstream feed, and an
ingestion/operations overhaul measured on a 402k-record corpus.

### Added — data and evidence

- **CISA SSVC enrichment (fourth feed).** CISA Vulnrichment decision points are
  ingested verbatim (never merged into a composite) and exposed as an `ssvc`
  block on every record plus an `ssvc-active` priority view.
- **Exploit-tagged references.** The CVE record's own references tagged `exploit`
  (CNA _and_ the ADP array) become a first-class signal: a stored flag, corpus
  coverage on the overview (`46,463 tagged · 259 also KEV`), an
  `exploit ref` badge on Priority, Search and Watch rows with the linked
  references, an Explore filter (`?exploit=tagged`) and an API parameter.
  The label is explicit everywhere: a publisher classification, never a verified
  proof of exploitation.
- **Time-to-exploitation Sankey.** Publication cohort → days until KEV
  confirmation, with pinned selections, node drill-down, per-flow counts and
  shares, and a flow dialog that lists the records.
- **Publication volume by month, week and day**, each with its own honest window
  (12/24 months, 26/52 weeks, 30/90 days).
- **Relation graph rebuild:** bipartite CVE → attribute → records, deterministic
  layout, drill-down dialog with filter/sort/paging.
- **Fastest confirmations** card with the delay metric and both dates.
- **Browser-private watch list** (localStorage only, no accounts, no server
  record) and a **dark theme**.

### Changed — ingestion and operations

- **Upstream ref resolution fixed.** `git fetch` moves the remote-tracking ref,
  not the local branch; the importer now follows `refs/remotes/origin/<branch>`.
  Before this, the corpus sat 11 days behind while logging successful fetches.
- **Import cost:** content receipts are the git tree id (no 4.3 GB re-hash),
  FTS deletes go by rowid (an UNINDEXED `cve_id` delete scanned 396k documents
  per update, ~50 minutes for one 17.5k-record catch-up), KEV reads the corpus
  once per import instead of once per catalog entry, identical EPSS CSVs are not
  re-inserted, and every import logs `cve-import-phase` timings.
- **EPSS retention window** (`EPSS_RETENTION_DAYS`, default 90 days, matching the
  API's per-record history cap), pruned inside the import, with the window and
  the oldest retained date stated on the methodology page.
- **Aggregate cache freshness:** the worker refreshes when the accepted EPSS date
  or CVE revision moves, not only when the cache is empty (stale cache made every
  overview render fall back to live full-corpus queries: 4.2 s vs 0.26 s).
- **Restore drill as a command** (`RUN_RESTORE_ONCE` / `RESTORE_DIR`) and a
  rehearsed drill documented with its numbers.
- Dropped a redundant EPSS index (`idx_epss_daily_score_date`): identical query
  plans, ~180 MB and one index update per inserted row saved.

### Security

- **Nonce-based Content-Security-Policy** on page HTML
  (`script-src 'self' 'nonce-…' 'strict-dynamic'`, `object-src 'none'`,
  `frame-ancestors 'none'`, `base-uri 'self'`); API responses keep their stricter
  `default-src 'none'` policy. `style-src` keeps `'unsafe-inline'` because React
  writes inline style attributes for chart geometry.
- API hardening carried over: rate limiting with headers, XFF handling, bounded
  parameters, parameterized SQL, `nosniff`/`DENY`/`no-referrer`/Permissions-Policy.

### Fixed

- Watch list could silently lose a change: the `localStorage` write lived inside
  a React state updater, so the double invocation restored the pre-toggle list.
- Exploit tags in `containers.adp` were dropped (the field is an array, and the
  extractor treated it as an object), so a badge could appear without its link.
- `dataDir: ":memory:"` created a literal `:memory:` directory instead of using
  SQLite's in-memory database.
- Test suite: the benchmark no longer rewrites a committed evidence file on every
  run; several order-dependent specs were made deterministic.

### Upgrade notes

- Migrations 005–007 apply automatically on the first write open. Migration 005
  rebuilds the full-text index once (≈400k documents); migration 007 drops the
  redundant EPSS index.
- New optional environment variables: `EPSS_RETENTION_DAYS` (default 90),
  `SSVC_REPO_DIR`.
- API: `/api/v1` unchanged in shape; additions are `ssvc`,
  `exploitReferenceStatus`/`exploitReferences` and the `?exploit=tagged` filter.

## 1.0.0 — 2026-10-28

First public release: CVE List V5 + CISA KEV + FIRST EPSS ingestion, explainable
priority lists (no composite score), Change Radar and retained-snapshot replay,
search with filters, a versioned read-only API with OpenAPI docs, nightly verified
backups, Apache-2.0 licence.
