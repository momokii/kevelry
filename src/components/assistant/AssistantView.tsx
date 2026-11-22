// The desk as a pure function of its state.
//
// Nothing here fetches, aborts, or parses: `AssistantDesk` owns the transport and
// the reducer, and this file turns the result into markup. That split is what
// makes all six states renderable in a test — a state that can only be reached by
// driving a live stream is a state nobody can review.
//
// The layout is the design: transcript on the left, provenance ledger sticky on
// the right, one left edge for question, answer, evidence and composer. There are
// no bubbles and no speaker indentation — the hairline beside the prose is the
// only rule, and it sits outside the text column so every line still starts at
// the same x.

import type { RefObject } from "react";

import { AssistantLedger } from "./AssistantLedger";
import {
  MAX_QUESTION_CHARS,
  counterVisible,
  disabledFault,
  formatCount,
  formatRemaining,
  formatResetInstant,
  type AssistantFault,
  type AssistantGate,
  type AssistantTurn,
} from "./assistant-state";
import type { AssistantSuggestion } from "@/lib/ai/suggestions";

export type AssistantStatus = "idle" | "streaming";

export interface AssistantViewProps {
  gate: AssistantGate;
  /** Already-scoped to this corpus; empty when the corpus cannot answer any. */
  suggestions: readonly AssistantSuggestion[];
  turns: readonly AssistantTurn[];
  fault: AssistantFault | null;
  status: AssistantStatus;
  /** Words for the tool the server is running right now. */
  activity: string | null;
  draft: string;
  /** The pinned record the next question is asked about. */
  aboutCve: string | null;
  /** Live seconds remaining for a timed fault (rate limit, budget reset). */
  remainingSeconds: number | null;
  ledgerOpen: boolean;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  onDraftChange: (value: string) => void;
  onSubmit: () => void;
  onStop: () => void;
  onRetry: () => void;
  onSuggestion: (question: string) => void;
  onClearContext: () => void;
  onLedgerToggle: (open: boolean) => void;
}

const SUBMIT_KEY_HINT = "Enter sends · Shift+Enter adds a line";

function FaultMeta({
  fault,
  remainingSeconds,
}: {
  fault: AssistantFault;
  remainingSeconds: number | null;
}) {
  const reset = formatResetInstant(fault.resetAt);
  const waiting = remainingSeconds !== null && remainingSeconds > 0;
  const parts: string[] = [fault.code];
  if (fault.kind === "rate-limited") {
    parts.push(waiting ? `retry in ${formatRemaining(remainingSeconds)}` : "retry now");
  }
  if (fault.kind === "budget") {
    if (reset !== null) parts.push(`resets at ${reset}`);
    if (waiting) parts.push(formatRemaining(remainingSeconds));
  }
  if (fault.envVar !== null) parts.push(fault.envVar);
  return <p className="assistant-fault-meta">{parts.join(" · ")}</p>;
}

function FaultPanel({
  fault,
  remainingSeconds,
  onRetry,
}: {
  fault: AssistantFault;
  remainingSeconds: number | null;
  onRetry: () => void;
}) {
  return (
    <div
      className={`assistant-fault is-${fault.kind}`}
      role="alert"
      data-testid="assistant-fault"
      data-kind={fault.kind}
      data-code={fault.code}
    >
      <p className="assistant-fault-headline">{fault.headline}</p>
      <p className="assistant-fault-next">{fault.next}</p>
      {fault.detail !== null ? <p className="assistant-fault-detail">{fault.detail}</p> : null}
      <FaultMeta fault={fault} remainingSeconds={remainingSeconds} />
      {fault.retryable ? (
        <button type="button" className="btn btn-sm assistant-retry" onClick={onRetry}>
          Ask again
        </button>
      ) : null}
    </div>
  );
}

function EmptyDesk({
  suggestions,
  onSuggestion,
}: {
  suggestions: readonly AssistantSuggestion[];
  onSuggestion: (question: string) => void;
}) {
  if (suggestions.length === 0) {
    return (
      <p className="assistant-empty-note" data-testid="assistant-suggestions-empty">
        This corpus has no KEV, exploit-tagged or EPSS-scored records yet, so there is nothing to
        suggest. Ask about the corpus itself — coverage is always answerable.
      </p>
    );
  }
  return (
    <div className="assistant-empty" data-testid="assistant-empty">
      <p className="assistant-empty-lede">
        Start with a question this snapshot can answer today. Each count is read when the page
        loads.
      </p>
      <ul className="assistant-suggestions" aria-label="Suggested questions">
        {suggestions.map((suggestion) => (
          <li key={suggestion.id}>
            <button
              type="button"
              className="assistant-suggestion"
              data-testid={`assistant-suggestion-${suggestion.id}`}
              onClick={() => {
                onSuggestion(suggestion.question);
              }}
            >
              <span className="assistant-suggestion-question">{suggestion.question}</span>
              <span className="assistant-suggestion-count">
                {formatCount(suggestion.count)} {suggestion.countLabel}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function TurnBlock({
  turn,
  streaming,
  isLast,
  activity,
}: {
  turn: AssistantTurn;
  streaming: boolean;
  isLast: boolean;
  activity: string | null;
}) {
  const live = turn.settled;
  const progress = Math.min(86, 22 + turn.tools.length * 18);
  return (
    <article className="assistant-turn" data-testid="assistant-turn">
      <p className="assistant-question-label">
        You asked{turn.aboutCve !== null ? ` about ${turn.aboutCve}` : ""}
      </p>
      <p className="assistant-question">{turn.question}</p>
      {streaming && isLast ? (
        <p className="assistant-activity" role="status" data-testid="assistant-activity">
          {streamingWord(turn, activity)}
        </p>
      ) : null}
      <div className="assistant-answer" aria-live={live ? "polite" : "off"}>
        {!live && turn.answer === "" ? (
          <div className="assistant-progress" aria-hidden="true" data-testid="assistant-progress">
            <span style={{ width: `${String(progress)}%` }} />
          </div>
        ) : null}
        {turn.answer === "" ? null : (
          <p
            key={live ? "settled" : "streaming"}
            className={`assistant-prose${live ? " is-settled" : ""}`}
            data-testid="assistant-answer"
          >
            {turn.answer}
          </p>
        )}
        {turn.citations.length > 0 ? (
          <div className="assistant-citations">
            <p className="assistant-citations-label">Cited</p>
            <ul className="assistant-chip-row" aria-label="Cited records">
              {turn.citations.map((id) => (
                <li key={id}>
                  <a
                    className="assistant-chip"
                    href={`/explore?q=${encodeURIComponent(id)}`}
                    data-testid="assistant-citation"
                  >
                    <span className="assistant-chip-id">{id}</span>
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
      {turn.stopped ? (
        <p className="assistant-turn-note" data-testid="assistant-stopped">
          Stopped before the answer finished. What is above is what arrived.
        </p>
      ) : null}
      {turn.settled && !turn.stopped && turn.answer === "" ? (
        <p className="assistant-turn-note">The turn ended before it wrote an answer.</p>
      ) : null}
    </article>
  );
}

/** The current activity, or a word that says what the stream is doing right now. */
function streamingWord(turn: AssistantTurn, activity: string | null): string {
  if (activity !== null) return activity;
  if (turn.answer !== "") return "writing the answer…";
  if (turn.tools.length > 0) return "reading what the last call returned…";
  return "the model is deciding what to look up…";
}

function Composer({
  draft,
  status,
  disabled,
  aboutCve,
  inputRef,
  onDraftChange,
  onSubmit,
  onStop,
  onClearContext,
}: {
  draft: string;
  status: AssistantStatus;
  disabled: boolean;
  aboutCve: string | null;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  onDraftChange: (value: string) => void;
  onSubmit: () => void;
  onStop: () => void;
  onClearContext: () => void;
}) {
  const streaming = status === "streaming";
  const tooLong = draft.length > MAX_QUESTION_CHARS;
  const sendBlocked = disabled || streaming || draft.trim() === "" || tooLong;
  return (
    <form
      className="assistant-composer"
      data-testid="assistant-composer"
      onSubmit={(event) => {
        event.preventDefault();
        if (!sendBlocked) onSubmit();
      }}
    >
      {aboutCve !== null ? (
        <div className="assistant-context" data-testid="assistant-context">
          <span className="assistant-context-label">about</span>
          <a className="assistant-chip assistant-context-link" href={`/explore?q=${aboutCve}`}>
            <span className="assistant-chip-id">{aboutCve}</span>
          </a>
          <button
            type="button"
            className="assistant-context-clear"
            aria-label={`Stop scoping questions to ${aboutCve}`}
            onClick={onClearContext}
          >
            ×
          </button>
        </div>
      ) : null}
      <label className="sr-only" htmlFor="assistant-question">
        Your question about this corpus
      </label>
      <textarea
        id="assistant-question"
        ref={inputRef}
        className="assistant-well"
        name="question"
        rows={3}
        value={draft}
        maxLength={MAX_QUESTION_CHARS}
        placeholder="Which KEV additions this week are also above 10% EPSS?"
        disabled={disabled}
        readOnly={streaming}
        aria-readonly={streaming ? true : undefined}
        aria-describedby="assistant-composer-hint assistant-composer-privacy"
        onChange={(event) => {
          onDraftChange(event.target.value);
        }}
        onKeyDown={(event) => {
          if (event.key !== "Enter" || event.shiftKey) return;
          // Enter sends; Shift+Enter is a newline. Mid-composition Enter belongs
          // to the input method, not to the desk.
          if (event.nativeEvent.isComposing) return;
          event.preventDefault();
          if (!sendBlocked) onSubmit();
        }}
      />
      <div className="assistant-composer-foot">
        <p className="assistant-composer-hint" id="assistant-composer-hint">
          {streaming ? "Answering — Stop ends it and keeps what arrived." : SUBMIT_KEY_HINT}
        </p>
        {counterVisible(draft.length) ? (
          <p className="assistant-counter" data-testid="assistant-counter">
            {draft.length} / {MAX_QUESTION_CHARS}
          </p>
        ) : null}
        {streaming ? (
          <button
            type="button"
            className="btn assistant-stop"
            data-testid="assistant-stop"
            onClick={onStop}
          >
            Stop
          </button>
        ) : (
          <button
            type="submit"
            className="btn btn-primary assistant-send"
            data-testid="assistant-send"
            disabled={sendBlocked}
          >
            Send
          </button>
        )}
      </div>
      <p className="assistant-composer-privacy" id="assistant-composer-privacy">
        The transcript lives in this tab and nowhere else — a reload starts clean, and neither the
        question nor the answer is written to this browser's storage.
      </p>
    </form>
  );
}

function DisabledDesk({ fault }: { fault: AssistantFault }) {
  return (
    <div className="assistant-disabled" data-testid="assistant-disabled">
      <p className="assistant-disabled-headline">{fault.headline}</p>
      <p className="assistant-disabled-next">{fault.next}</p>
      <dl className="assistant-disabled-facts">
        <dt>Reason</dt>
        <dd>{fault.disabledReason ?? "unknown"}</dd>
        <dt>Variable</dt>
        <dd className="mono">{fault.envVar ?? "AI_ENABLED"}</dd>
      </dl>
      <p className="assistant-disabled-note">
        There is no composer in this state: the desk does not pretend to take a question it cannot
        send.
      </p>
    </div>
  );
}

export function AssistantView(props: AssistantViewProps) {
  const {
    gate,
    suggestions,
    turns,
    fault,
    status,
    activity,
    draft,
    aboutCve,
    remainingSeconds,
    ledgerOpen,
    inputRef,
    onDraftChange,
    onSubmit,
    onStop,
    onRetry,
    onSuggestion,
    onClearContext,
    onLedgerToggle,
  } = props;

  if (!gate.enabled) {
    return <DisabledDesk fault={disabledFault(gate.reason)} />;
  }

  const disabled = fault !== null && (fault.kind === "disabled" || fault.kind === "budget");
  return (
    <div className="assistant-desk">
      <div className="assistant-main">
        <section
          className="assistant-transcript"
          role="log"
          aria-label="Transcript"
          aria-live="polite"
          data-testid="assistant-transcript"
        >
          {turns.length === 0 ? (
            // A question this desk cannot send is not offered: a budget or a
            // disabled gate leaves the transcript column to the fault panel.
            disabled ? null : (
              <EmptyDesk suggestions={suggestions} onSuggestion={onSuggestion} />
            )
          ) : (
            turns.map((turn, index) => (
              <TurnBlock
                key={turn.id}
                turn={turn}
                streaming={status === "streaming"}
                isLast={index === turns.length - 1}
                activity={activity}
              />
            ))
          )}
        </section>

        {fault !== null ? (
          <FaultPanel fault={fault} remainingSeconds={remainingSeconds} onRetry={onRetry} />
        ) : null}

        <Composer
          draft={draft}
          status={status}
          disabled={disabled}
          aboutCve={aboutCve}
          inputRef={inputRef}
          onDraftChange={onDraftChange}
          onSubmit={onSubmit}
          onStop={onStop}
          onClearContext={onClearContext}
        />
      </div>

      <AssistantLedger turns={turns} open={ledgerOpen} onToggle={onLedgerToggle} />
    </div>
  );
}
