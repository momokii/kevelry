# V4 AI Chat — Credential & Capability Research

Status: probe complete (two rounds: reachability, then capability). No secret
values are recorded in this file; the key is referenced by location only.

## 1. Credential facts

| Item                                         | Value                                                                                          |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Provider id                                  | `opencode-go` ("OpenCode Go")                                                                  |
| Endpoint base                                | `https://opencode.ai/inference/go/openai/v1`                                                   |
| Chat endpoint (full)                         | `POST https://opencode.ai/inference/go/openai/v1/chat/completions`                             |
| Model id (wire value, bare)                  | `deepseek-v4.1-flash`                                                                          |
| Required routing header                      | `x-opencode-session: <uuid>` — without it every request is `400 MissingSessionID`              |
| Expected env var (provider registry)         | `OPENCODE_API_KEY`                                                                             |
| Where the key actually lives on this machine | `~/.local/share/opencode/auth.json`, object key `opencode-go`, field `key` (mode `-rw-------`) |
| SDK protocol declared by the registry        | `npm: @ai-sdk/openai-compatible`                                                               |
| Docs                                         | https://opencode.ai/v2/docs/console/go/                                                        |

**The key is not in the process environment.** `OPENCODE_API_KEY` is absent, and so
are `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `ANTHROPIC_API_KEY` and any `*_BASE_URL`.
Only `PI_PROVIDER` and `T3_MCP_BEARER_TOKEN` are present, both from the local T3
harness and unrelated. A container or CI runtime gets no key by inheritance: the
deployment must be handed `OPENCODE_API_KEY` explicitly, or the feature cannot
authenticate.

**API shape.** OpenAI-compatible paths and body schema (`messages`, `tools`,
`stream`, `image_url` parts), so an OpenAI-compatible client works — **but it is
not a drop-in endpoint**, because of the session header above. That header is the
single largest integration constraint: a naive SDK call fails with a `400` that
reads like an auth problem when auth is fine.

## 2. Capability matrix

| Capability                        | Verdict        | Evidence                                                                                                                                       |
| --------------------------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Plain completion / reachability   | **VERIFIED**   | `200`, assistant message returned, `usage.total_tokens` populated                                                                              |
| Session header is mandatory       | **VERIFIED**   | without it `400 {"type":"MissingSessionID"}`, rejected pre-inference, `$0.00` billed                                                           |
| Tool calling, complete arguments  | **VERIFIED**   | `200`, `message.tool_calls[0]` = `{id, type:"function", function:{name, arguments}}` with **complete JSON** `arguments` at a real token budget |
| Vision, actual reading            | **VERIFIED**   | a PNG of an advisory was read back as `CVE-2021-44228`; a long unbroken token can truncate mid-word                                            |
| Streaming (`stream: true`)        | **VERIFIED**   | `200`, `data:` chunks, terminal `data: [DONE]`; `stream_options.include_usage` yields a final usage chunk                                      |
| `usage` block shape               | **VERIFIED**   | OpenAI-compatible counters plus `usage.opencode.list_cost` and `reasoning_tokens`                                                              |
| Reasoning model behaviour         | **VERIFIED**   | thinking tokens precede output; `max_tokens` under ~512 truncates tool arguments and short answers                                             |
| Context window = 1,000,000 tokens | **UNVERIFIED** | provider registry (`~/.cache/opencode/models.json`), documented only, not probed                                                               |
| Max output = 384,000 tokens       | **UNVERIFIED** | same registry source, documented only                                                                                                          |
| Rate limits                       | **UNVERIFIED** | https://opencode.ai/v2/docs/console/go/ states none numerically; nothing probed                                                                |
| Availability of other model ids   | **UNVERIFIED** | no `/v1/models` probe was run; only `deepseek-v4.1-flash` is confirmed                                                                         |
| Price stability                   | **UNVERIFIED** | `list_cost` observed twice, no pricing page pinned                                                                                             |

Registry metadata for `deepseek-v4.1-flash` ("DeepSeek V4.1 Flash 1017") claims
`limit: {context: 1000000, output: 384000}`, `modalities: {input: [text, image],
output: [text]}`, `tool_call: true`, `reasoning: true`, `attachment: true`,
`temperature: true`. Treat every one of those as a vendor claim except where the
table above says **VERIFIED**.

## 3. Probe evidence

| #   | Probe                                                 | Status | Result                                                                                              |
| --- | ----------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------- |
| —   | first attempt, three probes, no `x-opencode-session`  | `400`  | `{"type":"error","error":{"type":"MissingSessionID", …}}` — all three, pre-inference, no charge     |
| 1   | tools + `"look up CVE-2021-44228"`, tiny `max_tokens` | `200`  | `finish_reason: "length"`, one `tool_calls` entry, `function.arguments: ""` (budget spent thinking) |
| 2   | vision, `image_url` data URI, tiny `max_tokens`       | `200`  | `finish_reason: "length"`, `content: ""` — accepted at transport, nothing read                      |
| 3   | streaming, `"say ok"`, `max_tokens: 8`                | `200`  | 7 `data:` chunks, `[DONE]` present                                                                  |
| 4   | tools + `"look up CVE-2021-44228"`, `max_tokens: 512` | `200`  | **complete** `arguments` JSON; the tool name and every argument intact                              |
| 5   | vision, PNG advisory, `max_tokens: 512`               | `200`  | read `CVE-2021-44228` from the image; a long unbroken word came back truncated, not misread         |
| 6   | streaming with `stream_options.include_usage: true`   | `200`  | text deltas, then one terminal chunk carrying the `usage` block, then `[DONE]`                      |

Billing metadata observed on the tool probes: `billing_source: "go"` (subscription
allowance), `usage.opencode.list_cost` ≈ `$0.0000639` for a one-line schema turn,
`allowance charged` ≈ `$0.0000383`, `cost: 0`. The `400`s incurred no inference.
Total probe spend is negligible — and **the cost per real turn is not**: a
298-token prompt was billed for a one-line tool schema, so an eight-tool prompt is
the dominant fixed cost of every turn.

## 4. The `usage` block

Paths that were observed, recorded verbatim because the budget code reads them:

```
usage.prompt_tokens
usage.completion_tokens
usage.total_tokens
usage.reasoning_tokens              ← thinking tokens, counted inside completion
usage.opencode.list_cost            ← list price of the turn, USD
```

Read defensively. `usage.opencode` is a gateway extension, not an OpenAI field: a
gateway change can drop it without changing the status code. **An absent cost is
unknown, never zero** — the budget ledger must record "unknown" so a metering
regression cannot look like a free month.

## 5. The `max_tokens` floor is a correctness rule, not a tuning knob

The model is a reasoning model: it spends completion tokens thinking before it
emits anything. At `max_tokens` 8–32 the budget is consumed by reasoning, so:

- tool `arguments` come back as an empty string with a `tool_calls` entry present;
- a vision turn returns `content: ""` with `finish_reason: "length"`;
- a short prose answer is cut before its first sentence ends.

All three look exactly like "the model is broken" and none of them is. **Floor every
real turn at 512**, budget 1024 for an answer that cites records, and treat
`finish_reason: "length"` as a typed failure (`AI_TRUNCATED`) rather than a short
answer — a truncated answer that silently lacks its citations is the one failure
mode this feature cannot afford.

## 6. Still documented-only

Kept as claims, cited, and marked **UNVERIFIED** wherever a plan depends on them:

- Context window 1,000,000 / max output 384,000 — provider registry
  (`~/.cache/opencode/models.json`), no probe.
- Rate limits — no numeric limit is published at
  https://opencode.ai/v2/docs/console/go/; the app must assume first-party limit
  and back off on `429`.
- Other model ids — unprobed; the plan pins one model id in configuration.

## 7. Integration constraints for the app

1. **Session header on every request.** Generate a UUID per process (or per turn)
   and set `x-opencode-session` as a default header in the client. Without it the
   feature reports an auth failure that is not an auth failure.
2. **Key from env only.** `OPENCODE_API_KEY`, read once at startup, never logged,
   never echoed, never placed in an error payload. Missing key = feature disabled,
   not a broken feature.
3. **`max_tokens` ≥ 512**, and `finish_reason: "length"` is an error.
4. **The tool preamble is paid for every turn.** Keep eight tool definitions lean;
   prose descriptions cost prompt tokens on every request.
5. **Stream, and ask for usage.** `stream: true` plus
   `stream_options.include_usage: true` is the only way to get a terminal `usage`
   block on a streamed turn, and the only way to bill the budget honestly.
6. **Vision needs a real budget** (≥ 512) before image intake is trusted.
7. **This is a reselling gateway, not the official DeepSeek API.** Subscription
   allowance, gateway-owned rate limits, deprecation and pricing; no SLA. A `400`
   here is not always a client bug.

## 8. Risks

1. **Session header mandatory** — a `400 MissingSessionID` presents as an auth bug.
2. **Small `max_tokens` truncates reasoning-first output** — see §5.
3. **Vision truncation on long unbroken tokens** — a CVE id read from an image can
   arrive cut mid-digit, so every extracted id must be shape-validated and resolved
   against the database before it is shown as a record.
4. **Prompt size is the fixed cost** — eight tool definitions are paid on every
   turn, before the question.
5. **Key location is non-standard** — `auth.json`, not the environment; a runtime
   that is not this machine's opencode install has no key at all.
6. **Gateway control** — rate limits, model ids and pricing can change without a
   client change; there is no `/v1/models` confirmation for any id but this one.
7. **Cost metering is an extension field** — if `usage.opencode` disappears, an
   optional cost must read as unknown, never as zero.

## 9. Operator checklist

- Export `OPENCODE_API_KEY` to every runtime that is not this machine's opencode
  install; do not copy `auth.json` into an image.
- Send `x-opencode-session: <uuid>` on every request.
- Pin `https://opencode.ai/inference/go/openai/v1/chat/completions` and
  `deepseek-v4.1-flash` in configuration, not in code.
- Set `max_tokens ≥ 512`; budget 1024 for cited answers.
- Treat `finish_reason: "length"` as a failure, and an absent
  `usage.opencode.list_cost` as unknown cost.
- Re-probe before relying on anything in §6: context window, rate limits, other
  model ids.
