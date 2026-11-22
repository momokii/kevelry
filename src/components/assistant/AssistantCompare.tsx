// The compare disclosure beside the composer.
//
// Two ids, two inline messages, one fixed question. The component owns only the
// draft pair and the messages under the fields; the question it sends is built
// by `assistant-compare.ts`, so a browser test and a unit test assert the same
// string.
//
// Validation is inline and quiet: a field says what shape it wants as soon as
// the reader leaves it, and the button stays disabled until both are valid and
// different. Nothing is announced while typing — the message sits under the
// field it belongs to, where the reader is already looking.

"use client";

import { useState, type KeyboardEvent } from "react";

import {
  buildCompareQuestion,
  validateCompareField,
  validateComparePair,
  type CompareErrors,
} from "./assistant-compare";

const NO_ERRORS: CompareErrors = { a: null, b: null };

export interface AssistantCompareProps {
  /** True while the desk cannot take a question: streaming, budget, disabled. */
  disabled: boolean;
  onCompare: (question: string) => void;
}

export function AssistantCompare({ disabled, onCompare }: AssistantCompareProps) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [errors, setErrors] = useState<CompareErrors>(NO_ERRORS);

  const submit = (): void => {
    if (disabled) return;
    const validation = validateComparePair(a, b);
    if (!validation.ok) {
      setErrors(validation.errors);
      return;
    }
    onCompare(buildCompareQuestion(validation.pair));
    setA("");
    setB("");
    setErrors(NO_ERRORS);
  };

  const enterSubmit = (event: KeyboardEvent<HTMLInputElement>): void => {
    if (event.key !== "Enter") return;
    // The surrounding composer form sends a question on Enter; a compare field
    // owns its own Enter and never submits the wrong form.
    event.preventDefault();
    submit();
  };

  return (
    <details className="assistant-compare" data-testid="assistant-compare">
      <summary className="assistant-compare-summary">Compare two records</summary>
      <div className="assistant-compare-form" role="group" aria-label="Compare two records">
        <p className="assistant-compare-note">
          Each id is read on its own and answered as a field-by-field table: status, dates, CVSS,
          KEV, ransomware, EPSS and CWE. Never a fused score, and never a winner.
        </p>
        <div className="assistant-compare-fields">
          <div className="assistant-compare-field">
            <label htmlFor="assistant-compare-a">First record</label>
            <input
              id="assistant-compare-a"
              className="assistant-compare-input mono"
              type="text"
              name="compareA"
              value={a}
              placeholder="CVE-2021-44228"
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
              aria-invalid={errors.a !== null}
              aria-describedby={errors.a === null ? undefined : "assistant-compare-a-error"}
              data-testid="assistant-compare-a"
              onChange={(event) => {
                const next = event.target.value;
                setA(next);
                if (errors.a !== null) setErrors((current) => ({ ...current, a: null }));
              }}
              onBlur={() => {
                const message = validateCompareField(a);
                setErrors((current) => ({ ...current, a: message }));
              }}
              onKeyDown={enterSubmit}
            />
            {errors.a === null ? null : (
              <p className="assistant-compare-error" id="assistant-compare-a-error">
                {errors.a}
              </p>
            )}
          </div>
          <div className="assistant-compare-field">
            <label htmlFor="assistant-compare-b">Second record</label>
            <input
              id="assistant-compare-b"
              className="assistant-compare-input mono"
              type="text"
              name="compareB"
              value={b}
              placeholder="CVE-2021-45046"
              autoComplete="off"
              spellCheck={false}
              disabled={disabled}
              aria-invalid={errors.b !== null}
              aria-describedby={errors.b === null ? undefined : "assistant-compare-b-error"}
              data-testid="assistant-compare-b"
              onChange={(event) => {
                const next = event.target.value;
                setB(next);
                if (errors.b !== null) setErrors((current) => ({ ...current, b: null }));
              }}
              onBlur={() => {
                const message = validateCompareField(b);
                setErrors((current) => ({ ...current, b: message }));
              }}
              onKeyDown={enterSubmit}
            />
            {errors.b === null ? null : (
              <p className="assistant-compare-error" id="assistant-compare-b-error">
                {errors.b}
              </p>
            )}
          </div>
        </div>
        <button
          type="button"
          className="btn btn-sm assistant-compare-send"
          disabled={disabled}
          data-testid="assistant-compare-send"
          onClick={submit}
        >
          Compare
        </button>
      </div>
    </details>
  );
}
