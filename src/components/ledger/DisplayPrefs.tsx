"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

export const SUPPORTED_TIME_ZONES = [
  "Asia/Jakarta",
  "Asia/Singapore",
  "UTC",
  "Europe/London",
  "America/New_York",
  "America/Los_Angeles",
] as const;

export type SupportedTimeZone = (typeof SUPPORTED_TIME_ZONES)[number];

export const DEFAULT_TIME_ZONE: SupportedTimeZone = "Asia/Jakarta";

export const TIME_ZONE_STORAGE_KEY = "ledger-timezone";

export const TIME_ZONE_COOKIE = "ledger-timezone";

export const SUPPORTED_THEMES = ["light", "dark"] as const;

export type SupportedTheme = (typeof SUPPORTED_THEMES)[number];

export const DEFAULT_THEME: SupportedTheme = "light";

export const THEME_STORAGE_KEY = "ui-theme";

export const THEME_COOKIE = "ui-theme";

export function isSupportedTheme(value: string): value is SupportedTheme {
  return (SUPPORTED_THEMES as readonly string[]).includes(value);
}

export const WATCH_STORAGE_KEY = "ui-watch";

/** Maximum watched CVE IDs. Quota-guarded with an honest cap message. Local
 * storage only — never a cookie (200 IDs would ride on every request). */
export const WATCH_MAX_IDS = 200;

const WATCH_ID_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,}$/;

export function sanitizeWatchIds(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const entry of value) {
    if (typeof entry === "string" && WATCH_ID_PATTERN.test(entry) && !out.includes(entry)) {
      out.push(entry);
      if (out.length >= WATCH_MAX_IDS) break;
    }
  }
  return out;
}

export function isSupportedTimeZone(value: string): value is SupportedTimeZone {
  return (SUPPORTED_TIME_ZONES as readonly string[]).includes(value);
}

type DisplayPrefs = {
  timeZone: SupportedTimeZone;
  setTimeZone: (zone: SupportedTimeZone) => void;
  theme: SupportedTheme;
  setTheme: (theme: SupportedTheme) => void;
  watchedIds: readonly string[];
  toggleWatch: (cveId: string) => void;
};

const DisplayPrefsContext = createContext<DisplayPrefs | null>(null);

type DisplayPrefsProviderProps = {
  children: ReactNode;
  initialTimeZone?: string;
  initialTheme?: string;
};

export function DisplayPrefsProvider({
  children,
  initialTimeZone,
  initialTheme,
}: DisplayPrefsProviderProps) {
  const [timeZone, setTimeZoneState] = useState<SupportedTimeZone>(() =>
    initialTimeZone && isSupportedTimeZone(initialTimeZone) ? initialTimeZone : DEFAULT_TIME_ZONE,
  );
  const [theme, setThemeState] = useState<SupportedTheme>(() =>
    initialTheme && isSupportedTheme(initialTheme) ? initialTheme : DEFAULT_THEME,
  );
  // Watch list is browser-private state: it never leaves localStorage, so
  // anonymity holds by construction (no account, no server record).
  const [watchedIds, setWatchedIds] = useState<readonly string[]>([]);

  // The stored choice wins over the server-rendered initial value so a
  // returning visitor sees their zone without a full reload anywhere.
  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(TIME_ZONE_STORAGE_KEY);
      if (stored && isSupportedTimeZone(stored)) {
        setTimeZoneState((current) => (current === stored ? current : stored));
      }
      const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
      if (storedTheme && isSupportedTheme(storedTheme)) {
        setThemeState((current) => (current === storedTheme ? current : storedTheme));
        document.documentElement.dataset.theme = storedTheme;
      }
      try {
        const raw = window.localStorage.getItem(WATCH_STORAGE_KEY);
        if (raw !== null) {
          const parsed: unknown = JSON.parse(raw);
          const clean = sanitizeWatchIds(parsed);
          if (clean.length > 0) setWatchedIds(clean);
        }
      } catch {
        // Corrupt or unavailable storage: start unwatched.
      }
    } catch {
      // Private-mode storage failure: keep the in-memory zone.
    }
  }, []);

  const setTimeZone = useCallback((zone: SupportedTimeZone) => {
    setTimeZoneState(zone);
    try {
      window.localStorage.setItem(TIME_ZONE_STORAGE_KEY, zone);
      document.cookie = `${TIME_ZONE_COOKIE}=${encodeURIComponent(zone)}; path=/; max-age=31536000; SameSite=Lax`;
    } catch {
      // Storage failure keeps the in-memory zone for this page view.
    }
  }, []);

  const setTheme = useCallback((next: SupportedTheme) => {
    setThemeState(next);
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
      document.cookie = `${THEME_COOKIE}=${encodeURIComponent(next)}; path=/; max-age=31536000; SameSite=Lax`;
      document.documentElement.dataset.theme = next;
    } catch {
      // Storage failure keeps the in-memory theme for this page view.
    }
  }, []);

  const toggleWatch = useCallback((cveId: string) => {
    if (!WATCH_ID_PATTERN.test(cveId)) return;
    setWatchedIds((current) => {
      const next = current.includes(cveId)
        ? current.filter((id) => id !== cveId)
        : current.length >= WATCH_MAX_IDS
          ? current
          : [...current, cveId];
      if (next !== current) {
        try {
          window.localStorage.setItem(WATCH_STORAGE_KEY, JSON.stringify(next));
        } catch {
          // Quota or private mode: keep the in-memory list for this view.
        }
      }
      return next;
    });
  }, []);

  const value = useMemo(
    () => ({ timeZone, setTimeZone, theme, setTheme, watchedIds, toggleWatch }),
    [timeZone, setTimeZone, theme, setTheme, watchedIds, toggleWatch],
  );

  return <DisplayPrefsContext.Provider value={value}>{children}</DisplayPrefsContext.Provider>;
}

export function useDisplayPrefs(): DisplayPrefs {
  const prefs = useContext(DisplayPrefsContext);
  if (!prefs) {
    throw new Error("useDisplayPrefs must be used inside DisplayPrefsProvider");
  }
  return prefs;
}

export function useTimeZone(): SupportedTimeZone {
  return useDisplayPrefs().timeZone;
}

export function useTheme(): SupportedTheme {
  return useDisplayPrefs().theme;
}
