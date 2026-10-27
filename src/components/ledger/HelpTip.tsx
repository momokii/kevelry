"use client";

import { useEffect, useId, useRef, useState } from "react";
import type { ReactNode } from "react";

type HelpTipProps = {
  /** Short name of the explained term, used for the accessible label. Supplementary only. */
  term: string;
  children: ReactNode;
  testId?: string;
  /** Showcase-only: render open on first paint. */
  defaultOpen?: boolean;
};

/**
 * Accessible disclosure for a supplementary definition. The trigger is a real
 * button with aria-expanded/aria-controls; the panel opens on hover, focus,
 * and click, closes on Escape or click-outside, and returns focus to the
 * trigger on Escape. Panel text is always supplementary: the surrounding
 * prose must stand alone without it.
 */
export function HelpTip({ term, children, testId, defaultOpen = false }: HelpTipProps) {
  const [pinned, setPinned] = useState(defaultOpen);
  const [transient, setTransient] = useState(false);
  const [anchor, setAnchor] = useState<{ top: number; left: number; maxWidth: number } | null>(
    null,
  );
  const rootRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const contentId = useId();
  const open = pinned || transient;

  // Viewport-anchored bubble: measure the trigger on open and clamp into
  // the viewport so the panel never causes horizontal overflow and never
  // gets clipped by scroll containers. Dismiss on scroll/resize, like
  // click-outside and Escape.
  useEffect(() => {
    if (!open) {
      setAnchor(null);
      return;
    }
    const place = (): void => {
      const trigger = triggerRef.current;
      if (trigger === null) return;
      const rect = trigger.getBoundingClientRect();
      const maxWidth = Math.min(280, window.innerWidth - 32);
      const left = Math.max(16, Math.min(rect.left - 6, window.innerWidth - maxWidth - 16));
      setAnchor({ top: rect.bottom + 10, left, maxWidth });
    };
    place();
    const dismiss = (): void => {
      setPinned(false);
      setTransient(false);
    };
    window.addEventListener("scroll", place, { capture: true, passive: true });
    window.addEventListener("resize", dismiss);
    return () => {
      window.removeEventListener("scroll", place, { capture: true });
      window.removeEventListener("resize", dismiss);
    };
  }, [open]);

  const close = (returnFocus: boolean) => {
    setPinned(false);
    setTransient(false);
    if (returnFocus) {
      triggerRef.current?.focus();
    }
  };

  useEffect(() => {
    if (!open) {
      return;
    }
    const onPointerDown = (event: PointerEvent): void => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setPinned(false);
        setTransient(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        setPinned(false);
        setTransient(false);
      }
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <span
      ref={rootRef}
      className="ledger-helptip"
      data-testid={testId}
      onMouseEnter={() => setTransient(true)}
      onMouseLeave={() => setTransient(false)}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.stopPropagation();
          close(false);
        }
      }}
    >
      <button
        ref={triggerRef}
        type="button"
        className="ledger-helptip-trigger"
        aria-expanded={open}
        aria-controls={contentId}
        aria-describedby={open ? contentId : undefined}
        aria-label={`About ${term}`}
        data-testid={testId ? `${testId}-trigger` : undefined}
        onClick={() => {
          setPinned((current) => !current);
          setTransient(false);
        }}
        onFocus={() => setTransient(true)}
        onBlur={() => setTransient(false)}
      >
        <span className="ledger-helptip-glyph" aria-hidden="true">
          ?
        </span>
      </button>
      <span
        id={contentId}
        role="note"
        className="ledger-helptip-panel"
        hidden={!open}
        data-testid={testId ? `${testId}-panel` : undefined}
        style={
          anchor === null
            ? undefined
            : {
                position: "fixed",
                top: anchor.top,
                left: anchor.left,
                right: "auto",
                maxWidth: anchor.maxWidth,
              }
        }
      >
        {children}
      </span>
    </span>
  );
}
