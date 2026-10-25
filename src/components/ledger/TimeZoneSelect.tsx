"use client";

import { useDisplayPrefs } from "./DisplayPrefs";
import type { SupportedTimeZone } from "./DisplayPrefs";
import { SUPPORTED_TIME_ZONES } from "./DisplayPrefs";

type TimeZoneSelectProps = {
  testId?: string;
};

const ZONE_LABELS: Record<SupportedTimeZone, string> = {
  "Asia/Jakarta": "Jakarta (WIB)",
  "Asia/Singapore": "Singapore (SGT)",
  UTC: "UTC",
  "Europe/London": "London (GMT/BST)",
  "America/New_York": "New York (ET)",
  "America/Los_Angeles": "Los Angeles (PT)",
};

export function TimeZoneSelect({ testId = "timezone-select" }: TimeZoneSelectProps) {
  const { timeZone, setTimeZone } = useDisplayPrefs();

  return (
    <span className="ledger-timezone">
      <label className="ledger-meta" htmlFor={`${testId}-select`}>
        Display timezone
      </label>
      <select
        id={`${testId}-select`}
        className="ledger-timezone-select"
        value={timeZone}
        onChange={(event) => {
          const next = event.target.value;
          if (next === timeZone) {
            return;
          }
          setTimeZone(next as SupportedTimeZone);
        }}
        data-testid={testId}
      >
        {SUPPORTED_TIME_ZONES.map((zone) => (
          <option key={zone} value={zone}>
            {ZONE_LABELS[zone]}
          </option>
        ))}
      </select>
    </span>
  );
}
