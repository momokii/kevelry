"use client";

import { useEffect, useRef, useState } from "react";

import { HelpTip } from "../ledger/HelpTip";
import {
  EXPLORE_LIMIT_OPTIONS,
  type ExploreInitial,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
} from "./filter-meta";

const AUTO_SUBMIT_DELAY_MS = 150;

type ExploreFiltersProps = {
  initial: ExploreInitial;
};

/**
 * Native GET filter form with progressive auto-submit: checkbox, radio, and
 * select changes resubmit after a short debounce; the text query only submits
 * on Enter or Apply so typing never navigates. The Apply button and Clear
 * link keep the form fully usable with keyboard or without script.
 */
export function ExploreFilters({ initial }: ExploreFiltersProps) {
  const formRef = useRef<HTMLFormElement>(null);
  const timerRef = useRef<number | null>(null);
  const [hydrated, setHydrated] = useState(false);

  useEffect(() => {
    setHydrated(true);
  }, []);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
      }
    };
  }, []);

  const maybeAutoSubmit = (target: EventTarget | null): void => {
    if (!(target instanceof HTMLElement)) return;
    const kind = (target as HTMLInputElement).type;
    const auto = kind === "checkbox" || kind === "radio" || target.tagName === "SELECT";
    if (!auto) return;
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
    }
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      formRef.current?.requestSubmit();
    }, AUTO_SUBMIT_DELAY_MS);
  };

  const applyPreset = (days: number | null): void => {
    const form = formRef.current;
    if (form === null) return;
    const start = form.elements.namedItem("dateStart");
    const end = form.elements.namedItem("dateEnd");
    if (!(start instanceof HTMLInputElement) || !(end instanceof HTMLInputElement)) return;
    if (days === null) {
      start.value = "";
      end.value = "";
    } else {
      const endDate = new Date();
      const exclusiveEnd = new Date(
        Date.UTC(endDate.getUTCFullYear(), endDate.getUTCMonth(), endDate.getUTCDate() + 1),
      );
      end.value = exclusiveEnd.toISOString().slice(0, 10);
      start.value = new Date(exclusiveEnd.getTime() - days * 86_400_000).toISOString().slice(0, 10);
    }
    form.requestSubmit();
  };

  return (
    <form
      ref={formRef}
      method="get"
      action="/explore"
      aria-label="CVE search filters"
      data-testid="explore-filters"
      data-hydrated={hydrated ? "true" : "false"}
      className="ledger-explore-form"
      onChange={(event) => maybeAutoSubmit(event.target)}
    >
      <div className="ledger-search">
        <input
          className="ledger-search-input"
          type="search"
          name="q"
          defaultValue={initial.q}
          placeholder="Search CVE identifier or description"
          aria-label="Search CVE records"
          maxLength={200}
          data-testid="explore-query"
        />
        <button className="ledger-search-button" type="submit" data-testid="explore-submit">
          Search
        </button>
      </div>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Published date range{" "}
          <HelpTip term="date range filter" testId="explore-help-date">
            Compares the stored publication timestamp in UTC. The start binds inclusively, the end
            exclusively. Records with an unknown publication date are excluded as soon as either
            bound is set; they never match a bounded range.
          </HelpTip>
        </legend>
        <div className="date-range">
          <div className="date-fields">
            <label className="date-field" htmlFor="explore-date-start">
              <span>From · UTC</span>
              <input
                id="explore-date-start"
                type="date"
                name="dateStart"
                defaultValue={initial.dateStart}
                data-testid="explore-date-start"
              />
            </label>
            <span className="date-arrow" aria-hidden="true">
              →
            </span>
            <label className="date-field" htmlFor="explore-date-end">
              <span>Before · UTC</span>
              <input
                id="explore-date-end"
                type="date"
                name="dateEnd"
                defaultValue={initial.dateEnd}
                data-testid="explore-date-end"
              />
            </label>
          </div>
          <div className="date-presets" role="group" aria-label="Quick date ranges">
            <button
              type="button"
              className="date-preset"
              onClick={() => applyPreset(7)}
              data-testid="explore-preset-7"
            >
              7d
            </button>
            <button
              type="button"
              className="date-preset"
              onClick={() => applyPreset(30)}
              data-testid="explore-preset-30"
            >
              30d
            </button>
            <button
              type="button"
              className="date-preset"
              onClick={() => applyPreset(90)}
              data-testid="explore-preset-90"
            >
              90d
            </button>
            <button
              type="button"
              className="date-preset"
              onClick={() => applyPreset(365)}
              data-testid="explore-preset-365"
            >
              1y
            </button>
            <button
              type="button"
              className="date-preset"
              onClick={() => applyPreset(null)}
              data-testid="explore-preset-all"
            >
              All
            </button>
          </div>
          <p className="chart-note" style={{ margin: 0 }}>
            Start inclusive, end exclusive. Unknown dates are excluded from any bounded range.
          </p>
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Severity bands, primary CNA metric with version labels{" "}
          <HelpTip term="severity filter" testId="explore-help-severity">
            Bands come from the primary CNA CVSS only. ADP-only and metric-less records land in
            Unscored. CVSS v2-only records are Legacy and are never compared with v3/v4 scores.
          </HelpTip>
        </legend>
        <div className="ledger-filter-group" role="group" aria-label="Severity bands">
          {SEVERITY_ORDER.map((band) => (
            <label key={band} className="ledger-filter-chip ledger-explore-chip">
              <input
                type="checkbox"
                name="severity"
                value={band}
                defaultChecked={initial.severity.includes(band)}
                data-testid={`explore-severity-${band}`}
              />
              <span>{SEVERITY_LABELS[band]}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Known-exploited membership{" "}
          <HelpTip term="KEV filter" testId="explore-help-kev">
            Membership in the accepted CISA snapshot. Absence is not proof of no exploitation. The
            date added is the catalog date, not the date of first exploitation.
          </HelpTip>
        </legend>
        <div
          className="ledger-filter-group"
          role="radiogroup"
          aria-label="Known-exploited membership"
        >
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="all"
              defaultChecked={initial.kev === "all"}
              data-testid="explore-kev-all"
            />
            <span>Any KEV status</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="only"
              defaultChecked={initial.kev === "only"}
              data-testid="explore-kev-only"
            />
            <span>KEV-listed only</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="kev"
              value="excluded"
              defaultChecked={initial.kev === "excluded"}
              data-testid="explore-kev-excluded"
            />
            <span>Not KEV-listed</span>
          </label>
        </div>
      </fieldset>

      <fieldset className="ledger-explore-fieldset">
        <legend className="ledger-meta">
          Forecast presence, same snapshot, same model{" "}
          <HelpTip term="EPSS filter" testId="explore-help-epss">
            Dated forecast presence for this snapshot&apos;s model and score date — not severity,
            not popularity. Absent means no current row, never zero.
          </HelpTip>
        </legend>
        <div className="ledger-filter-group" role="radiogroup" aria-label="Forecast presence">
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="all"
              defaultChecked={initial.epss === "all"}
              data-testid="explore-epss-all"
            />
            <span>Any forecast status</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="present"
              defaultChecked={initial.epss === "present"}
              data-testid="explore-epss-present"
            />
            <span>Forecast present</span>
          </label>
          <label className="ledger-filter-chip ledger-explore-chip">
            <input
              type="radio"
              name="epss"
              value="absent"
              defaultChecked={initial.epss === "absent"}
              data-testid="explore-epss-absent"
            />
            <span>Forecast unavailable</span>
          </label>
        </div>
      </fieldset>

      <div className="ledger-explore-actions">
        <label className="ledger-explore-label" htmlFor="explore-limit">
          <span className="ledger-explore-caption">
            Results per page{" "}
            <HelpTip term="page size" testId="explore-help-limit">
              Bounded page size. Totals and cohort coverage may exceed the returned page.
            </HelpTip>
          </span>
          <select
            id="explore-limit"
            name="limit"
            defaultValue={String(initial.limit)}
            data-testid="explore-limit"
            className="ledger-snapshot-select"
          >
            {EXPLORE_LIMIT_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option} per page
              </option>
            ))}
          </select>
        </label>
        <button className="ledger-search-button" type="submit" data-testid="explore-apply">
          Apply filters
        </button>
        <a className="ledger-explore-clear" href="/explore" data-testid="explore-clear">
          Clear filters
        </a>
      </div>
    </form>
  );
}
