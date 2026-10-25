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

export function isSupportedTimeZone(value: string): value is SupportedTimeZone {
  return (SUPPORTED_TIME_ZONES as readonly string[]).includes(value);
}

type DisplayPrefs = {
  timeZone: SupportedTimeZone;
  setTimeZone: (zone: SupportedTimeZone) => void;
};

const DisplayPrefsContext = createContext<DisplayPrefs | null>(null);

type DisplayPrefsProviderProps = {
  children: ReactNode;
  initialTimeZone?: string;
};

export function DisplayPrefsProvider({ children, initialTimeZone }: DisplayPrefsProviderProps) {
  const [timeZone, setTimeZoneState] = useState<SupportedTimeZone>(() =>
    initialTimeZone && isSupportedTimeZone(initialTimeZone) ? initialTimeZone : DEFAULT_TIME_ZONE,
  );

  // The stored choice wins over the server-rendered initial value so a
  // returning visitor sees their zone without a full reload anywhere.
  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(TIME_ZONE_STORAGE_KEY);
      if (stored && isSupportedTimeZone(stored)) {
        setTimeZoneState((current) => (current === stored ? current : stored));
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

  const value = useMemo(() => ({ timeZone, setTimeZone }), [timeZone, setTimeZone]);

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
