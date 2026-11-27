# Empty-answer fix — the tool-round cap ends turns before any answer round

**Status:** diagnosis + plan only, no code changed · **Against:** 4.0.7 at `http://100.124.184.116:3100/assistant` · **Probe:** `Which KEV entries are due in the next 30 days?` · **Model:** `deepseek-v4.1-flash` (reasoning-first), `AI_MAX_ANSWER_TOKENS` unset → 4096.

## Measured: 2 of 8 runs (25 %) settled with no answer text

8 sequential POSTs to `/api/assistant/chat`, one user message each, SSE parsed per run. All 8 returned HTTP 200. With the six-take capture, 5 of 14 (36 %) turns were empty.

| #   | events (order)        | delta text | done | rounds | usage p / c / r     | class       |
| --- | --------------------- | ---------- | ---- | ------ | ------------------- | ----------- |
| 1   | tool×2, delta×114     | 1474 chars | yes  | 2      | 17200 / 2684 / 2129 | answer      |
| 2   | tool×14, delta×140    | 1647 chars | yes  | 2      | 30672 / 4603 / 3431 | answer      |
| 3   | delta, tool×13, delta | 1933 chars | yes  | 3      | 36800 / 3237 / 2023 | answer      |
| 4   | **tool×17, no delta** | **none**   | yes  | **4**  | 37023 / 3634 / 2971 | **(c) cap** |
| 5   | tool×15, delta        | 1673 chars | yes  | 3      | 37619 / 4874 / 3690 | answer      |
| 6   | delta, tool×13, delta | 1796 chars | yes  | 3      | 35313 / 4917 / 3700 | answer      |
| 7   | **tool×7, no delta**  | **none**   | yes  | **4**  | 26836 / 2902 / 2583 | **(c) cap** |
| 8   | tool×14, delta        | 1343 chars | yes  | 2      | 30672 / 3535 / 2481 | answer      |

Zero `error`, zero `retry`, zero `AI_TRUNCATED` frames in 8 runs — runs 4 and 7 contained **no `finish_reason: length` round at all**. They were not budget-starved.

**Run 4 quoted:** `done` with `rounds: 4`, `completion: 3634` of which `reasoning: 2971` (82 %), `tool` frames `list_priority`, `kev_window`, then 15× `get_cve`, and no `delta`. **Run 7:** same shape, 7 calls, last one `fetch_authoritative` (1 row, 0 ids) then 4× `get_cve`.

## Where the note comes from, and why the retry and the budget are innocent

`src/lib/ai/turn.ts:388-393` ends the turn the moment `rounds >= 4`:

```ts
if (rounds >= ASSISTANT_MAX_TOOL_ROUNDS) {
  yield * settle(totals, rounds); // citations + done, never checks answerText
  answered = true; // counts as answered, so the ledger bills it
  return;
}
```

`settle()` (`turn.ts:361-377`) emits `done` unconditionally, empty `answerText` included. The client maps `done` → `settled: true` (`AssistantDesk.tsx:340-357` `finishTurn`), and `AssistantView.tsx:402-404` renders the note when `turn.settled && !turn.stopped && turn.answer === ""`. So the message is **round-cap exhaustion reported as a successful turn** — not truncation, not an upstream error.

- Both empty-round retries are gated on `roundMaxTokens < answerMaxTokens` (`turn.ts:449`, `turn.ts:471`). Round 0 runs at `AI_MAX_TOKENS_DEFAULT` = 1024 (`turn.ts:400-401`), so only round 0 may retry; every later round already runs at 4096 and is refused. The round that actually runs out is round 4, never reached. `tests/ai-streaming.test.ts:695` pins that refusal; no test covers the cap-settle path.
- Answer budget is 4096 (`AI_MAX_ANSWER_TOKENS_DEFAULT`, `config.ts:49`; floor 512 in `clampMaxTokens`, `client.ts:223-225`). Nothing was cut by it. Raising it cannot help a turn that never writes prose.
- Prompt 26.8k–37.6k tokens, inside the window and the 60k session budget. Tool payloads are already capped (`KEV_WINDOW_ROW_CAP` 25, `WEB_FETCH_MAX_CHARS` = min(8000, `UNTRUSTED_MAX_CHARS`), a cut body flagged `truncated`), so the earlier "truncated fetch" is a labelled partial result, not an overflow.
- Wall clock is the real secondary risk: run 6 took 42.7 s of the 45 s `AI_REQUEST_TIMEOUT_MS` default. Any fix that re-sends a 37k prompt turns empties into `AI_TIMEOUT`s.

## Fix: guarantee an answer round, then retry it once with trimmed history

1. **Lock the last permitted round to prose** (`turn.ts:388-406`). While `rounds === ASSISTANT_MAX_TOOL_ROUNDS - 1`, pass `tools: []` — `buildPayload` (`client.ts:261-263`) already omits the field when empty, so no client change — plus a system line: no more tools, answer from the evidence gathered. That round already gets 4096. This makes an empty settle at the cap structurally impossible rather than merely less likely: 2/8 were still calling tools when the cap fired, so raising the cap to 6 or 8 only lowers the rate.
2. **Retry that final round once, trimmed** (`turn.ts:465-480`). Drop the `roundMaxTokens < answerMaxTokens` guard for it and, on retry, rebuild `conversation` keeping the opening tool results plus the last 4 tool messages — ~10k instead of 37k. A full re-send costs another $0.003–0.006 and 25–43 s against a 45 s deadline (run 6: 42.7 s), i.e. an untrimmed retry converts an empty turn into `AI_TIMEOUT`. `retriedEmptyRound` stays the one-way latch: at most one retry per turn.
3. **Never settle empty** (`turn.ts:361-377`). `settle()` asserts `answerText !== ""`; when it is empty the turn yields `{ type: "error", code: "AI_UPSTREAM_ERROR" }` naming the round it ran out on, and the fault panel states the reason. No `done` without text, ever.

Rejected: raising the answer budget (0/8 truncations), and tool-result caps as the primary fix (payloads already fit; step 2 trims only what the retry needs).

## Acceptance

- 8 consecutive runs of the probe question each emit ≥ 1 `delta` with text before `done` (baseline 6/8; capture 3/6 empty).
- `rounds <= 6`, `retry` ≤ 1 per turn, and a retry never re-sends the full history.
- Any turn that still cannot answer ends with `error` carrying code and reason; `done` with `answer === ""` is unreachable and the `AssistantView` note becomes dead copy.
- Tests: the cap path asserts the last round is sent without `tools`; an empty final round asserts `error`, not `done`; the retry asserts a trimmed message count.
- Cost ≤ $0.006 per turn, p95 latency ≤ 40 s of the 45 s deadline.
