"use client";

// The desk's behaviour: one POST, one AbortController, one transcript.
//
// Everything the server says arrives as an SSE frame and is folded into a single
// `AssistantTurn` — tools into the ledger, deltas into the prose, `citations`
// into chips, `done`/`error` into a settled turn plus, when it failed, a fault.
// Nothing is inferred: a chip exists only because the server's `citations` event
// named that id, and a ledger line exists only because a `tool` frame arrived.
//
// Two things are deliberately absent:
//
//  - no persistence. The transcript is React state; there is no localStorage, no
//    sessionStorage, no cookie. A reload is a new desk, and the compositor says so
//    in one line rather than leaving the reader to guess.
//  - no second parser. `assistant-sse.ts` handles frame boundaries; this file
//    only decides what each complete frame means.
//
// One image is held for the session, and each question decides whether to send
// it. `docs/plans/v4-image-context-fix.md` priced the payload at ≤912 prompt
// tokens, but price was never the question: the reader's consent was. So the
// payload is staged, a per-question `sendImage` decides, and every turn stores
// the answer it was given — a follow-up that says "explain that screenshot"
// carries the picture, and a plain policy question does not. The turn keeps only
// a thumbnail, so a long transcript never holds ten copies of two megabytes.

import { useCallback, useEffect, useRef, useState, type RefObject } from "react";

import { AssistantView } from "./AssistantView";
import { createAssistantSseParser, parseAssistantEvent } from "./assistant-sse";
import { briefFileName, buildBriefMarkdown } from "./assistant-brief";
import {
  readImageFile,
  refersToAttachment,
  toThumbnail,
  type AssistantAttachment,
} from "./assistant-image";
import {
  MAX_QUESTION_CHARS,
  faultFromCode,
  faultFromHttp,
  faultFromStreamError,
  formatToolArgs,
  toolActivity,
  type AssistantFault,
  type AssistantGate,
  type AssistantToolLine,
  type AssistantTurn,
} from "./assistant-state";
import type { AssistantSuggestion } from "@/lib/ai/suggestions";
import type { AssistantEvent } from "@/lib/ai/turn";

/** The route's own message cap; nine history messages fit inside its limit too. */
const MAX_HISTORY_MESSAGES = 10;
const MAX_HISTORY_CHARS = 11_000;

export interface AssistantDeskProps {
  gate: AssistantGate;
  suggestions: readonly AssistantSuggestion[];
  /** From `/assistant?cve=…`; validated by the page before it reaches here. */
  initialCveContext: string | null;
  /** `AI_MODEL`, printed in a downloaded brief. */
  modelId: string;
}

interface FaultState {
  fault: AssistantFault;
  /** When a timed fault lifts; null for faults that need a reload or an operator. */
  deadlineMs: number | null;
}

/**
 * The reader's answer to "use screenshot in this question", until the next send.
 *
 * `ask` is the absence of an answer, and is deliberately the reset value: after a
 * send the desk has no opinion about a question that has not been typed yet, and
 * the next question decides on its own words (`refersToAttachment`). `send` and
 * `skip` are the reader overriding that, in either direction.
 */
type ImageConsent = "ask" | "send" | "skip";

interface WireMessage {
  role: "user" | "assistant";
  content: string;
}

/** The stateless server takes the history the client holds, so the client sends it. */
export function buildHistory(turns: readonly AssistantTurn[], question: string): WireMessage[] {
  const history: WireMessage[] = [];
  for (const turn of turns) {
    if (!turn.settled || turn.answer === "") continue;
    history.push({ role: "user", content: turn.question });
    history.push({ role: "assistant", content: turn.answer });
  }
  history.push({ role: "user", content: question });
  const bounded = history.slice(-MAX_HISTORY_MESSAGES);
  let chars = bounded.reduce((total, message) => total + message.content.length, 0);
  while (bounded.length > 1 && chars > MAX_HISTORY_CHARS) {
    const removed = bounded.shift();
    chars -= removed?.content.length ?? 0;
  }
  return bounded;
}

function deadlineFor(fault: AssistantFault, nowMs: number): number | null {
  if (fault.retryAfterSeconds !== null) return nowMs + fault.retryAfterSeconds * 1000;
  const resetMs = fault.resetAt === null ? null : Date.parse(fault.resetAt);
  return resetMs !== null && Number.isFinite(resetMs) ? resetMs : null;
}

function remainingOf(state: FaultState | null, nowMs: number): number | null {
  if (state === null || state.deadlineMs === null) return null;
  return Math.max(0, Math.ceil((state.deadlineMs - nowMs) / 1000));
}

function networkFault(): AssistantFault {
  return {
    ...faultFromCode("AI_UPSTREAM_ERROR"),
    code: "NETWORK",
    headline: "The connection to the server dropped before the answer finished.",
    next: "Ask again. The transcript above is exactly what arrived.",
    retryable: true,
  };
}

export function AssistantDesk({
  gate,
  suggestions,
  initialCveContext,
  modelId,
}: AssistantDeskProps) {
  const [turns, setTurns] = useState<AssistantTurn[]>([]);
  const [draft, setDraft] = useState("");
  const [status, setStatus] = useState<"idle" | "streaming">("idle");
  const [activity, setActivity] = useState<string | null>(null);
  const [faultState, setFaultState] = useState<FaultState | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [aboutCve, setAboutCve] = useState<string | null>(initialCveContext);
  const [ledgerOpen, setLedgerOpen] = useState(true);
  const [image, setImage] = useState<AssistantAttachment | null>(null);
  const [imageFault, setImageFault] = useState<string | null>(null);
  /** Consent for the *next* question; see `ImageConsent`. */
  const [imageConsent, setImageConsent] = useState<ImageConsent>("ask");
  /** True once `×` has been pressed, so the composer can say what it meant. */
  const [imageRemoved, setImageRemoved] = useState(false);

  const inputRef: RefObject<HTMLTextAreaElement | null> = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const turnSeq = useRef(0);
  const toolSeq = useRef(0);
  const lastQuestion = useRef<string | null>(null);
  /** The consent the failed turn was sent with, so a retry re-sends the same one. */
  const lastSendImage = useRef(false);
  const turnsRef = useRef<AssistantTurn[]>([]);
  const imageSeq = useRef(0);
  turnsRef.current = turns;
  /** Whether the next question will carry the screenshot, as the chip shows it. */
  const pendingSendImage =
    image !== null &&
    (imageConsent === "send" || (imageConsent === "ask" && refersToAttachment(draft)));

  // One polite ticker, only while a timed fault is counting down.
  useEffect(() => {
    if (faultState === null || faultState.deadlineMs === null) return;
    const id = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => {
      window.clearInterval(id);
    };
  }, [faultState]);

  // A rate limit lifts on its own; a budget needs the reset (or an operator).
  useEffect(() => {
    if (faultState === null || faultState.fault.kind !== "rate-limited") return;
    const remaining = remainingOf(faultState, nowMs);
    if (remaining !== null && remaining <= 0) setFaultState(null);
  }, [faultState, nowMs]);

  // The ledger is a sticky column on a wide screen and a disclosure below the
  // transcript on a narrow one; a closed disclosure hides chips that prove an
  // answer, so the wide layout never allows it to close.
  useEffect(() => {
    const media = window.matchMedia("(min-width: 1024px)");
    const apply = (): void => {
      // Wide: the ledger is a column and always open. Narrow: it is a disclosure
      // below the transcript and starts folded, so it never pushes the composer
      // past the fold on a phone.
      setLedgerOpen(media.matches);
    };
    apply();
    media.addEventListener("change", apply);
    return () => {
      media.removeEventListener("change", apply);
    };
  }, []);

  useEffect(
    () => () => {
      abortRef.current?.abort();
    },
    [],
  );

  const updateTurn = useCallback((id: string, update: (turn: AssistantTurn) => AssistantTurn) => {
    setTurns((current) => current.map((turn) => (turn.id === id ? update(turn) : turn)));
  }, []);

  const finishTurn = useCallback(
    (id: string) => {
      setStatus("idle");
      setActivity(null);
      updateTurn(id, (turn) => ({ ...turn, settled: true }));
    },
    [updateTurn],
  );

  const applyEvent = useCallback(
    (id: string, event: AssistantEvent) => {
      if (event.type === "tool") {
        toolSeq.current += 1;
        const line: AssistantToolLine = {
          id: `tool-${String(toolSeq.current)}`,
          name: event.name,
          args: formatToolArgs(event.args),
          rows: event.rows,
          ok: event.ok,
          ids: Array.isArray(event.ids) ? event.ids : [],
        };
        setActivity(toolActivity(event.name, event.rows));
        updateTurn(id, (turn) => ({ ...turn, tools: [...turn.tools, line] }));
        return;
      }
      if (event.type === "delta") {
        setActivity(null);
        updateTurn(id, (turn) => ({ ...turn, answer: turn.answer + event.text }));
        return;
      }
      if (event.type === "retry") {
        // The server re-ran a round that hit its completion cap with nothing to
        // show. That is not a fault and needs no copy: the retried round's own
        // deltas or error arrive next, and inventing a "retrying…" line would
        // narrate plumbing the reader did not ask about.
        return;
      }
      if (event.type === "citations") {
        const records = Array.isArray(event.records) ? event.records : [];
        updateTurn(id, (turn) => ({ ...turn, citations: records }));
        return;
      }
      if (event.type === "unverified") {
        const ids = Array.isArray(event.ids) ? event.ids : [];
        updateTurn(id, (turn) => ({ ...turn, unverified: ids }));
        return;
      }
      if (event.type === "done") {
        // `done` also carries usage, which the desk does not display: the ledger
        // is about evidence, and a token count in the reader's face is not
        // evidence. Its `unverified` list is the one field kept: the event above
        // is the live path, and this fills the gap if that frame was lost.
        if (Array.isArray(event.unverified)) {
          const ids = event.unverified;
          updateTurn(id, (turn) =>
            turn.unverified.length > 0 ? turn : { ...turn, unverified: ids },
          );
        }
        return;
      }
      if (event.type === "error") {
        setFaultState({ fault: faultFromStreamError(event.code), deadlineMs: null });
        finishTurn(id);
      }
    },
    [finishTurn, updateTurn],
  );

  const ask = useCallback(
    async (rawQuestion: string, resendImage: boolean | null = null) => {
      const question = rawQuestion.trim().slice(0, MAX_QUESTION_CHARS);
      if (question === "") return;
      if (abortRef.current !== null) return;

      turnSeq.current += 1;
      const id = `turn-${String(turnSeq.current)}`;
      const scoped = aboutCve;
      // Consent is decided here, once, and stored on the turn: the attach
      // question sends it by default, a question that points at it ("explain
      // that screenshot") sends it again, and the reader's checkbox overrides
      // both. Every other question sends no payload at all.
      const attached = image;
      const sendImage =
        attached !== null &&
        (resendImage ??
          (imageConsent === "send" || (imageConsent === "ask" && refersToAttachment(question))));
      lastQuestion.current = question;
      lastSendImage.current = sendImage;
      const turn: AssistantTurn = {
        id,
        question,
        answer: "",
        settled: false,
        stopped: false,
        citations: [],
        unverified: [],
        tools: [],
        aboutCve: scoped,
        sendImage,
        // Only a question that sent the picture keeps a record of it: a turn
        // has a thumbnail because its request carried one, never otherwise.
        image:
          sendImage && attached !== null
            ? {
                id: attached.id,
                name: attached.name,
                mime: attached.mime,
                size: attached.size,
                thumb: attached.thumb,
              }
            : null,
      };
      setTurns((current) => [...current, turn]);
      setDraft("");
      setImageFault(null);
      // The next question starts with no opinion: its own words decide, and the
      // reader ticks the box to override that. `×` is the only thing that
      // removes the payload itself.
      setImageConsent("ask");
      setFaultState(null);
      setActivity(null);
      setStatus("streaming");
      // The composer keeps focus after send: the reader's hands stay where they
      // were, and the Stop control is one Tab away rather than a mouse trip.
      inputRef.current?.focus();

      const controller = new AbortController();
      abortRef.current = controller;
      const body: Record<string, unknown> = {
        messages: buildHistory(turnsRef.current, question),
      };
      if (scoped !== null) body.cveContext = scoped;
      // R1: the payload rides only on the questions that asked for it. The body
      // is the one place this can be wrong, so the condition is `sendImage` and
      // nothing else — not `attached !== null`.
      if (sendImage && attached !== null) body.image = { dataUrl: attached.dataUrl };

      try {
        const response = await fetch("/api/assistant/chat", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: controller.signal,
          cache: "no-store",
        });

        if (!response.ok) {
          let snapshot: unknown = null;
          try {
            snapshot = await response.json();
          } catch {
            snapshot = null;
          }
          const retryAfter = Number(response.headers.get("retry-after"));
          const fault = faultFromHttp({
            status: response.status,
            snapshot,
            retryAfterSeconds: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null,
          });
          setFaultState({
            fault,
            deadlineMs: deadlineFor(fault, Date.now()),
          });
          finishTurn(id);
          return;
        }

        if (response.body === null) {
          setFaultState({ fault: networkFault(), deadlineMs: null });
          finishTurn(id);
          return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        const parser = createAssistantSseParser();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value === undefined) continue;
          // `stream: true` holds a split code point until its bytes arrive.
          for (const payload of parser.push(decoder.decode(value, { stream: true }))) {
            const event = parseAssistantEvent(payload);
            if (event !== null) applyEvent(id, event);
          }
        }
        for (const payload of parser.push(decoder.decode())) {
          const event = parseAssistantEvent(payload);
          if (event !== null) applyEvent(id, event);
        }
        finishTurn(id);
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") {
          setActivity(null);
          setStatus("idle");
          updateTurn(id, (turn) => ({ ...turn, settled: true, stopped: true }));
          return;
        }
        setFaultState({ fault: networkFault(), deadlineMs: null });
        finishTurn(id);
      } finally {
        if (abortRef.current === controller) abortRef.current = null;
      }
    },
    [aboutCve, applyEvent, finishTurn, updateTurn, image, imageConsent],
  );

  const stop = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  const pickImage = useCallback((file: File) => {
    imageSeq.current += 1;
    const seq = imageSeq.current;
    void readImageFile(file).then(async (result) => {
      // A slower earlier read never overwrites a later choice.
      if (seq !== imageSeq.current) return;
      if (!result.ok) {
        setImageFault(result.message);
        return;
      }
      // The record's downscaled copy is made once, here, so a transcript never
      // has to hold two megabytes to show a picture it already sent.
      const thumb = await toThumbnail(result.image.dataUrl);
      if (seq !== imageSeq.current) return;
      setImage({ ...result.image, id: seq, thumb });
      setImageFault(null);
      // R2/R4: the question this picture was attached for sends it. The reader
      // can still untick that before pressing Enter; × removes the file itself.
      setImageConsent("send");
      setImageRemoved(false);
    });
  }, []);

  const downloadBrief = useCallback(
    (turn: AssistantTurn) => {
      const markdown = buildBriefMarkdown({
        turn,
        modelId,
        origin: window.location.origin,
      });
      const url = URL.createObjectURL(
        new Blob([markdown], { type: "text/markdown;charset=utf-8" }),
      );
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = briefFileName(new Date());
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      // Revoking synchronously can cancel the download in some browsers.
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
      }, 0);
    },
    [modelId],
  );

  const retry = useCallback(() => {
    const previous = lastQuestion.current;
    setFaultState(null);
    // The failed turn's own consent, not the composer's current state: a retry
    // is the same question, so it sends what that question sent.
    if (previous !== null) void ask(previous, lastSendImage.current);
  }, [ask]);

  const disabled =
    faultState !== null &&
    (faultState.fault.kind === "disabled" ||
      faultState.fault.kind === "budget" ||
      faultState.fault.kind === "rate-limited");
  const remainingSeconds = remainingOf(faultState, nowMs);

  return (
    <AssistantView
      gate={gate}
      suggestions={suggestions}
      turns={turns}
      fault={faultState?.fault ?? null}
      status={status}
      activity={activity}
      draft={draft}
      aboutCve={aboutCve}
      image={image}
      imageFault={imageFault}
      imageRemoved={imageRemoved}
      sendImage={pendingSendImage}
      remainingSeconds={remainingSeconds}
      ledgerOpen={ledgerOpen}
      inputRef={inputRef}
      onDraftChange={setDraft}
      onImagePick={pickImage}
      onImageConsentChange={(next) => {
        setImageConsent(next ? "send" : "skip");
      }}
      onImageRemove={() => {
        // R5: the payload, the staged image and the consent all go, at once and
        // for good. Nothing here can re-arm it — only a fresh attach can.
        setImage(null);
        setImageFault(null);
        setImageConsent("ask");
        setImageRemoved(true);
      }}
      onCompare={(question) => {
        if (disabled) return;
        void ask(question);
      }}
      onFollowUp={(question) => {
        if (disabled) return;
        void ask(question);
      }}
      onBrief={downloadBrief}
      onSubmit={() => {
        if (disabled) return;
        void ask(draft);
      }}
      onStop={stop}
      onRetry={retry}
      onSuggestion={(question) => {
        if (disabled) return;
        void ask(question);
      }}
      onClearContext={() => {
        setAboutCve(null);
      }}
      onLedgerToggle={setLedgerOpen}
    />
  );
}
