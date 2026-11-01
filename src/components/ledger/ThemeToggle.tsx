"use client";

import { SUPPORTED_THEMES, useDisplayPrefs, type SupportedTheme } from "./DisplayPrefs";

const THEME_LABELS: Record<SupportedTheme, string> = {
  light: "Light",
  dark: "Dark",
};

export function ThemeToggle({ testId = "theme-toggle" }: { testId?: string }) {
  const { theme, setTheme } = useDisplayPrefs();

  return (
    <span className="ledger-timezone">
      <span className="ledger-meta" id={`${testId}-label`}>
        Display theme
      </span>
      <span
        className="pill segmented"
        role="group"
        aria-labelledby={`${testId}-label`}
        data-testid={testId}
      >
        {SUPPORTED_THEMES.map((option) => (
          <button
            key={option}
            type="button"
            className={`btn btn-sm ${theme === option ? "btn-primary" : "btn-ghost"}`}
            aria-pressed={theme === option}
            data-testid={`${testId}-${option}`}
            onClick={() => {
              if (option !== theme) setTheme(option);
            }}
          >
            {THEME_LABELS[option]}
          </button>
        ))}
      </span>
    </span>
  );
}
