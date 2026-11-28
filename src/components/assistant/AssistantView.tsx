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

import { useEffect, useState, type RefObject } from "react";

import { HelpTip } from "../ledger/HelpTip";
import { AssistantCompare } from "./AssistantCompare";
import { AssistantLedger } from "./AssistantLedger";
import { buildFollowUps } from "./assistant-followups";
import { formatImageSize, type AssistantAttachment } from "./assistant-image";
import { renderAnswer } from "./render-answer";
import {
  ELAPSED_TICK_MS,
  HISTORY_TRIMMED_NOTE,
  MAX_QUESTION_CHARS,
  counterVisible,
  disabledFault,
  formatCount,
  formatElapsed,
  formatRemaining,
  formatResetInstant,
  REFUSAL_LABEL,
  unverifiedNote,
  webSources,
  workingStage,
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
  /** The screenshot attached to the next question, already validated. */
  image: AssistantAttachment | null;
  /** Why the last attach attempt was refused, in plain language. */
  imageFault: string | null;
  /**
   * Whether the next question will carry the screenshot.
   *
   * The reader's consent, not a consequence: `×` is removal of the file, and this
   * is the answer to "use it for this one?".
   */
  sendImage: boolean;
  /** True once `×` has removed the file, so the composer can say what that meant. */
  imageRemoved: boolean;
  /** Live seconds remaining for a timed fault (rate limit, budget reset). */
  remainingSeconds: number | null;
  ledgerOpen: boolean;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  onDraftChange: (value: string) => void;
  onImagePick: (file: File) => void;
  onImageConsentChange: (next: boolean) => void;
  onImageRemove: () => void;
  onCompare: (question: string) => void;
  onFollowUp: (question: string) => void;
  onBrief: (turn: AssistantTurn) => void;
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
  return (
    <p className="assistant-fault-meta">
      {parts.join(" · ")}
      {fault.kind === "budget" ? (
        <>
          {" "}
          <HelpTip term="session / daily budget" testId="assistant-tip-budget">
            A session budget counts this conversation; the daily budget counts everyone on this
            deployment and resets at 00:00 UTC. The panel names which one ran out.
          </HelpTip>
        </>
      ) : null}
    </p>
  );
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
        suggest. Ask about the corpus itself — coverage is always answerable. It will not write
        exploit code or give targeting advice.
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
      {/* The edges, stated once: a desk that never says what it will not do
          invites the reader to assume it will do anything. */}
      <p className="assistant-empty-capacity" data-testid="assistant-empty-capacity">
        Ask about records in this deployment — its catalogs, scores, and dates. It will not write
        exploit code or give targeting advice.
      </p>
    </div>
  );
}

function TurnBlock({
  turn,
  streaming,
  onFollowUp,
  onBrief,
}: {
  turn: AssistantTurn;
  streaming: boolean;
  onFollowUp: (question: string) => void;
  onBrief: (turn: AssistantTurn) => void;
}) {
  const live = turn.settled;
  // Derived from the ledger, never from the prose: a chip that names an id the
  // turn never read would be a hallucination with a button on it. A failed turn
  // is not finished, and a refusal has nothing to finish, so neither offers a
  // follow-up or an export — the refused question is not a citation to build on.
  const complete = turn.settled && !turn.stopped && !turn.failed && turn.refusal !== true;
  const followUps = complete ? buildFollowUps(turn) : [];
  // The one web source a turn may have read (the plan allows one fetch a turn),
  // as a chip in the citation area: the host, plus the word `web` so the warning
  // hue is never the only signal that this evidence is not the dataset.
  const web = webSources(turn);
  return (
    <article className="assistant-turn" data-testid="assistant-turn">
      <p className="assistant-question-label">
        You asked{turn.aboutCve !== null ? ` about ${turn.aboutCve}` : ""}
      </p>
      <p className="assistant-question">{turn.question}</p>
      {turn.contextTrimmed ? (
        // What the request carried, stated once and quietly: the answer stands on
        // its own, but a follow-up that stopped referring to the start of the
        // conversation now has a visible reason.
        <p className="assistant-turn-note" data-testid="assistant-context-trimmed">
          {HISTORY_TRIMMED_NOTE}
        </p>
      ) : null}
      {turn.image === null ? null : (
        // The screenshot is part of the question, not a gallery beside it: it
        // sits directly under the words it was attached to. `<details>` is the
        // whole viewer — no dialog, no focus trap, no scroll lock — and the
        // expanded copy is the retained thumbnail at full width, because the
        // turn deliberately does not keep the payload.
        <figure className="assistant-shot" data-testid="assistant-shot">
          <details className="assistant-shot-details" data-testid="assistant-shot-details">
            <summary className="assistant-shot-summary">
              <img
                className="assistant-shot-thumb"
                src={turn.image.thumb}
                alt="Attached screenshot"
              />
              <span className="assistant-shot-meta">
                <span className="assistant-shot-name">{turn.image.name}</span>
                <span className="assistant-shot-size">
                  {formatImageSize(turn.image.size)} ·{" "}
                  {turn.image.mime.replace("image/", "").toUpperCase()}
                </span>
              </span>
            </summary>
            <div className="assistant-shot-full">
              {/* The summary already names it; a second reading is noise. */}
              <img
                className="assistant-shot-full-image"
                src={turn.image.thumb}
                alt=""
                aria-hidden="true"
              />
            </div>
          </details>
          {turn.sendImage ? (
            <figcaption className="assistant-shot-note" data-testid="assistant-shot-note">
              Attached with this question
            </figcaption>
          ) : null}
        </figure>
      )}
      <div className="assistant-answer" aria-live={live ? "polite" : "off"}>
        {!live && turn.answer === "" ? (
          // An indeterminate sweep, not a percentage: the desk cannot know how
          // far a turn is, and a bar that invents progress is a number with a
          // lie behind it. It goes once prose arrives — the prose is movement.
          <div
            className="assistant-progress is-running"
            aria-hidden="true"
            data-testid="assistant-progress"
          >
            <span />
          </div>
        ) : null}
        {turn.answer === "" ? null : (
          // The answer is rendered, never parsed as markup: `renderAnswer` turns
          // the model's text into React nodes (blocks of paragraphs, lists,
          // tables, inline emphasis and vetted links). The measure and rhythm
          // come from the same `.assistant-prose` class a plain answer uses. An
          // id in the prose links only when the server cited it, so prose can
          // never mint a citation the ledger does not carry.
          <div
            key={live ? "settled" : "streaming"}
            className={`assistant-prose is-formatted${live ? " is-settled" : ""}`}
            data-testid="assistant-answer"
          >
            {renderAnswer(turn.answer, { verifiedIds: turn.citations })}
          </div>
        )}
        {turn.unverified.length > 0 ? (
          // Above the citations, in the app's voice: the answer is not blocked,
          // but an id without a tool behind it is never allowed to look sourced.
          <p
            className="assistant-unverified"
            data-testid="assistant-unverified"
            data-count={String(turn.unverified.length)}
          >
            {unverifiedNote(turn.unverified)}
            <HelpTip term="unverified ids" testId="assistant-tip-unverified">
              An id the answer named that the records did not contain. It is text, not a link,
              because this dataset cannot confirm it.
            </HelpTip>
          </p>
        ) : null}
        {turn.refusal === true ? (
          // A refusal is an answer: quiet, beside the prose it describes, and
          // never an alert. The panel is for faults; nothing here failed.
          <p className="assistant-turn-note" data-testid="assistant-refusal">
            {REFUSAL_LABEL}
          </p>
        ) : null}
        {web.length > 0 ? (
          // Web evidence sits in the citation area, after the record chips: same
          // shape, different provenance, and the only warning hue on this page.
          <ul
            className="assistant-chip-row assistant-web-sources"
            aria-label="Web sources"
            data-testid="assistant-web-sources"
          >
            {web.map((source) => (
              <li key={source.url}>
                <a
                  className="assistant-chip assistant-chip-web"
                  href={source.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid="assistant-web-chip"
                >
                  <span className="assistant-chip-web-mark">web</span>
                  <span className="assistant-chip-id">{source.host}</span>
                </a>
              </li>
            ))}
          </ul>
        ) : null}
        {turn.citations.length > 0 ? (
          // The turn's union, one line closed: the rail is already per call, so
          // these chips answer "what can this answer cite" and nothing else.
          <details className="assistant-citations" data-testid="assistant-citations">
            <summary className="assistant-citations-summary">
              <span data-testid="assistant-citations-label">
                {String(turn.citations.length)} record
                {turn.citations.length === 1 ? "" : "s"} cited
              </span>
              <span
                onClick={(event) => {
                  // The trigger is its own control: opening the tip must not
                  // also fold or unfold the chips under it.
                  event.stopPropagation();
                }}
              >
                <HelpTip term="cited" testId="assistant-tip-cited">
                  Records the answer's numbers came from. The same ids appear in the rail under the
                  call that returned them.
                </HelpTip>
              </span>
            </summary>
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
          </details>
        ) : null}
      </div>
      {followUps.length > 0 ? (
        <div className="assistant-followups" data-testid="assistant-followups">
          <p className="assistant-citations-label">Follow up</p>
          <ul className="assistant-chip-row" aria-label="Follow-up questions">
            {followUps.map((followUp) => (
              <li key={followUp.id}>
                <button
                  type="button"
                  className="assistant-followup"
                  data-testid={`assistant-followup-${followUp.kind}`}
                  onClick={() => {
                    onFollowUp(followUp.question);
                  }}
                >
                  {followUp.question}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {complete && turn.answer !== "" ? (
        <div className="assistant-turn-actions">
          <button
            type="button"
            className="btn btn-sm assistant-brief"
            data-testid="assistant-brief"
            onClick={() => {
              onBrief(turn);
            }}
          >
            Download brief
          </button>
        </div>
      ) : null}
      {turn.stopped ? (
        <p className="assistant-turn-note" data-testid="assistant-stopped">
          Stopped before the answer finished. What is above is what arrived.
        </p>
      ) : null}
      {turn.failed && turn.answer !== "" ? (
        // The mark on a partial answer: the fault panel names what went wrong,
        // and this says what that means for the text above it. Without it a
        // half-sentence reads as a finished thought that stopped early.
        <p className="assistant-turn-note" data-testid="assistant-incomplete">
          Incomplete: the answer stopped before it finished. What is above is what arrived.
        </p>
      ) : null}
      {turn.settled && !turn.failed && !turn.stopped && turn.answer === "" ? (
        // A settled turn with no text and no fault. The server no longer emits
        // this — `settle()` turns an empty answer into `AI_EMPTY_ANSWER` — so
        // the sentence is a fallback for a turn whose `done` frame outran its
        // error, never the reading of a failure the fault panel already names.
        <p className="assistant-turn-note">The turn ended before it wrote an answer.</p>
      ) : null}
    </article>
  );
}

/**
 * The working row: one polite live region that names the stage, proves the turn
 * is alive and offers Stop, in that order.
 *
 * The counter is mounted with the row, so it starts at zero on send and its
 * interval dies on settle or Stop — no reset logic, no tick running behind an
 * idle desk. The counter is hidden from assistive technology because a quarter-
 * second tick is noise; the region's accessible text then changes only when the
 * stage does. Stop keeps its name, and its 44px box keeps the row's height
 * identical to the idle footnote, so nothing shifts when a turn starts.
 */
function WorkingRow({ stage, onStop }: { stage: string; onStop: () => void }) {
  const [elapsedMs, setElapsedMs] = useState(0);
  useEffect(() => {
    const startedAt = Date.now();
    const id = window.setInterval(() => {
      setElapsedMs(Date.now() - startedAt);
    }, ELAPSED_TICK_MS);
    return () => {
      window.clearInterval(id);
    };
  }, []);
  return (
    <div
      className="assistant-working"
      role="status"
      aria-live="polite"
      data-testid="assistant-working"
    >
      <span className="assistant-working-stage" data-testid="assistant-working-stage">
        {stage}
      </span>
      <span
        className="assistant-working-elapsed"
        aria-hidden="true"
        data-testid="assistant-working-elapsed"
      >
        {formatElapsed(elapsedMs)}
      </span>
      <button
        type="button"
        className="btn assistant-stop"
        data-testid="assistant-stop"
        onClick={onStop}
      >
        Stop
      </button>
    </div>
  );
}

/**
 * What a screenshot is good for, one native disclosure beside the attach control.
 *
 * A `<details>` is the whole interaction: focusable, opened by Enter or Space,
 * no JavaScript, no focus trap. Closed by default, because the reader who knows
 * what to attach should not have to read a list to find the button.
 */
function ImageGuide() {
  return (
    <details className="assistant-image-guide" data-testid="assistant-image-guide">
      <summary className="assistant-image-guide-summary">What works</summary>
      <div className="assistant-image-guide-body">
        <p className="assistant-image-guide-purpose">
          The image is only used to find CVE ids. Each id is then checked against this dataset, and
          an id that does not resolve is reported as not here.
        </p>
        <p className="assistant-image-guide-heading">Works</p>
        <ul className="assistant-image-guide-list">
          <li>A vendor advisory page showing a CVE id</li>
          <li>An NVD or CVE record page</li>
          <li>A scanner report or ticket listing CVEs</li>
          <li>A PDF page screenshot that carries a CVE id</li>
        </ul>
        <p className="assistant-image-guide-heading">Does not work</p>
        <ul className="assistant-image-guide-list">
          <li>A game scoreboard or a photo</li>
          <li>A dashboard with no CVE id, vendor or product name</li>
        </ul>
        {/* Stated as behaviour, not as a caveat: a refusal is the desk doing its
            job, and a reader who expects an error will read it as one. */}
        <p className="assistant-image-guide-refusal">
          If the image has no CVE id in it, the answer says so. That is the desk working, not a
          failure.
        </p>
      </div>
    </details>
  );
}

function Composer({
  draft,
  status,
  stage,
  disabled,
  aboutCve,
  image,
  imageInContext,
  imageFault,
  imageRemoved,
  sendImage,
  inputRef,
  onDraftChange,
  onImagePick,
  onImageConsentChange,
  onImageRemove,
  onCompare,
  onSubmit,
  onStop,
  onClearContext,
}: {
  draft: string;
  status: AssistantStatus;
  /** What the running turn is doing, already worded. */
  stage: string;
  disabled: boolean;
  aboutCve: string | null;
  image: AssistantAttachment | null;
  /**
   * True once a turn in the transcript carries this attachment: only then is
   * there something retained to show, name and revoke. Before the first send the
   * intake preview is the whole story and a second chip would be a duplicate.
   */
  imageInContext: boolean;
  imageFault: string | null;
  /** What `×` meant, said once where the chip used to be. */
  imageRemoved: boolean;
  /** Whether the next question carries the screenshot — the chip's checkbox. */
  sendImage: boolean;
  inputRef?: RefObject<HTMLTextAreaElement | null>;
  onDraftChange: (value: string) => void;
  onImagePick: (file: File) => void;
  onImageConsentChange: (next: boolean) => void;
  onImageRemove: () => void;
  onCompare: (question: string) => void;
  onSubmit: () => void;
  onStop: () => void;
  onClearContext: () => void;
}) {
  const [dragging, setDragging] = useState(false);
  const streaming = status === "streaming";
  const busy = disabled || streaming;
  const tooLong = draft.length > MAX_QUESTION_CHARS;
  const sendBlocked = busy || draft.trim() === "" || tooLong;
  return (
    <form
      className={`assistant-composer${dragging ? " is-dragging" : ""}${streaming ? " is-working" : ""}`}
      data-testid="assistant-composer"
      onSubmit={(event) => {
        event.preventDefault();
        if (!sendBlocked) onSubmit();
      }}
      onDragOver={(event) => {
        if (busy || !event.dataTransfer.types.includes("Files")) return;
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => {
        setDragging(false);
      }}
      onDrop={(event) => {
        setDragging(false);
        if (busy) return;
        event.preventDefault();
        const file = event.dataTransfer.files[0];
        if (file !== undefined) onImagePick(file);
      }}
      onPaste={(event) => {
        if (busy) return;
        const file = Array.from(event.clipboardData.files).find((candidate) =>
          candidate.type.startsWith("image/"),
        );
        if (file === undefined) return;
        // An image paste is an attachment, not text; take it and keep the draft.
        event.preventDefault();
        onImagePick(file);
      }}
    >
      <div className="assistant-image" data-testid="assistant-image-intake">
        <div className="assistant-image-row">
          {image === null || imageInContext ? (
            // The input fills the visible label: the target is 44px, and the
            // native control keeps its own keyboard behaviour.
            <label className="assistant-image-pick">
              <input
                id="assistant-image-input"
                className="assistant-image-input"
                type="file"
                accept="image/png,image/jpeg,image/webp"
                disabled={busy}
                aria-describedby="assistant-image-note"
                data-testid="assistant-image-input"
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  // Reset the value so picking the same file twice fires again.
                  event.target.value = "";
                  if (file !== undefined) onImagePick(file);
                }}
              />
              <span>Attach a screenshot</span>
            </label>
          ) : (
            // Staged, not yet sent. Once a turn carries it the intake goes back
            // to its empty state — the chip above the field owns what is in
            // context — so one screenshot is never shown twice, and the picker is
            // ready for the next one.
            <div className="assistant-image-preview" data-testid="assistant-image-preview">
              <img
                className="assistant-image-thumb"
                src={image.dataUrl}
                alt=""
                aria-hidden="true"
              />
              <div className="assistant-image-meta">
                <p className="assistant-image-name">{image.name}</p>
                <p className="assistant-image-size">
                  {formatImageSize(image.size)} · {image.mime.replace("image/", "").toUpperCase()}
                </p>
              </div>
              <button
                type="button"
                className="assistant-image-remove"
                aria-label={`Remove ${image.name}`}
                data-testid="assistant-image-remove"
                disabled={busy}
                onClick={onImageRemove}
              >
                Remove
              </button>
            </div>
          )}
          {/* Beside the control, not under it: the guidance adds no height to a
              sticky composer until it is opened. */}
          <ImageGuide />
        </div>
        <p className="assistant-image-note" id="assistant-image-note">
          PNG, JPEG or WebP, up to 1.5 MB. The image is only used to find CVE ids, and every id is
          checked against the dataset before it is used.
        </p>
        {imageFault === null ? null : (
          <p className="assistant-image-fault" role="alert" data-testid="assistant-image-fault">
            {imageFault}
          </p>
        )}
      </div>
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
      {image !== null && imageInContext ? (
        // The attachment, and the one question it is for. The checkbox is the
        // consent: checked when this picture was just attached, or when the
        // question typed below points at it, and unticked by the reader to send
        // this one without it. `×` is not that — it removes the file.
        <div className="assistant-context" data-testid="assistant-image-context">
          <label className="assistant-image-consent">
            <input
              type="checkbox"
              checked={sendImage}
              data-testid="assistant-image-consent"
              onChange={(event) => {
                onImageConsentChange(event.target.checked);
              }}
            />
            <span>use screenshot in this question</span>
          </label>
          {/* Plain text, not a chip: nothing here navigates, and a pill would
              offer a click that does not exist. */}
          <span className="assistant-context-file">{image.name}</span>
          <button
            type="button"
            className="assistant-context-clear"
            aria-label={`Remove ${image.name} from context`}
            data-testid="assistant-image-context-remove"
            onClick={onImageRemove}
          >
            ×
          </button>
        </div>
      ) : null}
      {imageRemoved && image === null ? (
        // One sentence, once, where the chip was: `×` deleted the payload, so
        // nothing will carry it again until something is attached again.
        <p className="assistant-image-removed" data-testid="assistant-image-removed">
          Screenshot removed — it will not be sent again.
        </p>
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
        aria-describedby={
          streaming
            ? "assistant-composer-privacy"
            : "assistant-composer-hint assistant-composer-privacy"
        }
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
        {streaming ? (
          <WorkingRow stage={stage} onStop={onStop} />
        ) : (
          <>
            <p className="assistant-composer-hint" id="assistant-composer-hint">
              {SUBMIT_KEY_HINT}
            </p>
            {counterVisible(draft.length) ? (
              <p className="assistant-counter" data-testid="assistant-counter">
                {draft.length} / {MAX_QUESTION_CHARS}
              </p>
            ) : null}
            <button
              type="submit"
              className="btn btn-primary assistant-send"
              data-testid="assistant-send"
              disabled={sendBlocked}
            >
              Send
            </button>
          </>
        )}
      </div>
      <AssistantCompare disabled={busy} onCompare={onCompare} />
      <p className="assistant-composer-privacy" id="assistant-composer-privacy">
        The transcript and any screenshot live in this tab and nowhere else — a reload starts clean,
        and neither is written to this browser's storage.
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
    image,
    imageFault,
    imageRemoved,
    sendImage,
    remainingSeconds,
    ledgerOpen,
    inputRef,
    onDraftChange,
    onImagePick,
    onImageConsentChange,
    onImageRemove,
    onCompare,
    onFollowUp,
    onBrief,
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
  // The last turn is the one being streamed: the working row describes it.
  const lastTurn = turns.at(-1) ?? null;
  const stage =
    lastTurn === null ? "the model is deciding what to look up…" : workingStage(lastTurn, activity);
  // Derived from the transcript, not stored: the chip exists because a turn
  // actually carried this attachment, which is the only reason it is in context.
  const imageInContext =
    image !== null && turns.some((turn) => turn.image !== null && turn.image.id === image.id);
  return (
    <div className="assistant-desk">
      <div className="assistant-main">
        {/* The transcript's own heading. Without it the first `h3` an answer
            renders skips a level under the page `h1` — the renderer clamps
            model headings to `h3`/`h4`, so the missing level has to be the
            region's. It is outside the live region: a heading inside
            `role="log"` would be re-announced on every delta. */}
        <h2 className="sr-only">Answer</h2>
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
            turns.map((turn) => (
              <TurnBlock
                key={turn.id}
                turn={turn}
                streaming={status === "streaming"}
                onFollowUp={onFollowUp}
                onBrief={onBrief}
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
          stage={stage}
          disabled={disabled}
          aboutCve={aboutCve}
          image={image}
          imageInContext={imageInContext}
          imageFault={imageFault}
          imageRemoved={imageRemoved}
          sendImage={sendImage}
          inputRef={inputRef}
          onDraftChange={onDraftChange}
          onImagePick={onImagePick}
          onImageConsentChange={onImageConsentChange}
          onImageRemove={onImageRemove}
          onCompare={onCompare}
          onSubmit={onSubmit}
          onStop={onStop}
          onClearContext={onClearContext}
        />
      </div>

      <AssistantLedger turns={turns} open={ledgerOpen} onToggle={onLedgerToggle} />
    </div>
  );
}
