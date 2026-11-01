"use client";

import { useEffect, useState } from "react";

import { useDisplayPrefs, WATCH_MAX_IDS } from "../ledger/DisplayPrefs";
import { TimeText } from "../ledger/TimeText";

interface WatchSignals {
  kevListed: boolean;
  kevDateAdded: string | null;
  epssKnown: boolean;
  epssPercent: string | null;
  epssDate: string | null;
  cvssKnown: boolean;
  cvssScore: number | null;
  cvssVersion: string | null;
  publishedAt: string | null;
  excerpt: string | null;
}

type WatchRow =
  | { status: "loading" }
  | {
      status: "ready";
      id: string;
      title: string;
      officialUrl: string;
      signals: WatchSignals;
    }
  | { status: "missing"; id: string }
  | { status: "failed"; id: string };

function officialFallback(cveId: string): string {
  return `https://www.cve.org/CVERecord?id=${cveId}`;
}

async function fetchRow(cveId: string): Promise<WatchRow> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/cves/${encodeURIComponent(cveId)}`, {
      headers: { accept: "application/json" },
    });
  } catch {
    return { status: "failed", id: cveId };
  }
  if (response.status === 404) return { status: "missing", id: cveId };
  if (!response.ok) return { status: "failed", id: cveId };
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return { status: "failed", id: cveId };
  }
  const data = (body as { data?: Record<string, unknown> }).data;
  if (data === undefined) return { status: "failed", id: cveId };
  const kev = data.kev as { listed?: boolean; dateAdded?: string | null } | undefined;
  const epss = data.epss as
    { status?: string; value?: number | null; scoreDate?: string | null } | undefined;
  const cvss = data.cvssPrimary as
    { status?: string; baseScore?: number | null; version?: string | null } | undefined;
  const publishedAt = data.publishedAt;
  const excerpt = data.excerpt;
  const title = data.title;
  const officialUrl = data.officialUrl;
  return {
    status: "ready",
    id: cveId,
    title: typeof title === "string" && title !== "" ? title : cveId,
    officialUrl:
      typeof officialUrl === "string" && officialUrl !== "" ? officialUrl : officialFallback(cveId),
    signals: {
      kevListed: kev?.listed === true,
      kevDateAdded: typeof kev?.dateAdded === "string" ? kev.dateAdded : null,
      epssKnown: epss?.status === "known" && typeof epss.value === "number",
      epssPercent:
        epss?.status === "known" && typeof epss.value === "number"
          ? (epss.value * 100).toFixed(2)
          : null,
      epssDate: typeof epss?.scoreDate === "string" ? epss.scoreDate : null,
      cvssKnown: cvss?.status === "known" && typeof cvss.baseScore === "number",
      cvssScore: typeof cvss?.baseScore === "number" ? cvss.baseScore : null,
      cvssVersion: typeof cvss?.version === "string" ? cvss.version : null,
      publishedAt: typeof publishedAt === "string" ? publishedAt : null,
      excerpt: typeof excerpt === "string" && excerpt !== "" ? excerpt : null,
    },
  };
}

export function WatchView() {
  const { watchedIds, toggleWatch } = useDisplayPrefs();
  const [rows, setRows] = useState<WatchRow[]>([]);

  useEffect(() => {
    let cancelled = false;
    setRows(watchedIds.map((): WatchRow => ({ status: "loading" })));
    if (watchedIds.length === 0) return;
    void Promise.all(watchedIds.map((id) => fetchRow(id))).then((settled) => {
      if (!cancelled) setRows(settled);
    });
    return () => {
      cancelled = true;
    };
  }, [watchedIds]);

  if (watchedIds.length === 0) {
    return (
      <div className="ledger-section" data-testid="watch-empty">
        <h2>No watched CVEs yet</h2>
        <p className="ledger-meta">
          Star any row on Search or Priority with the star control; the list lives in this browser
          only. No account, no server record — clearing browser storage unwatches everything.
        </p>
      </div>
    );
  }

  return (
    <section
      className="ledger-section"
      aria-labelledby="watch-list-heading"
      data-testid="watch-list"
    >
      <h2 id="watch-list-heading">
        Watching {watchedIds.length} of {WATCH_MAX_IDS} records
      </h2>
      <div className="result-list">
        {rows.map((row, index) => {
          const id = watchedIds[index] ?? `row-${index}`;
          if (row.status === "loading") {
            return (
              <article className="ledger-row" key={id} data-testid={`watch-row-${id}`}>
                <span className="ledger-row-id">{id}</span>
                <p className="ledger-meta">Loading retained snapshot…</p>
              </article>
            );
          }
          if (row.status === "missing" || row.status === "failed") {
            return (
              <article className="ledger-row" key={id} data-testid={`watch-row-${id}`}>
                <span className="ledger-row-id">{id}</span>
                <p className="ledger-meta">
                  {row.status === "missing"
                    ? "No longer PUBLISHED in the retained snapshot; it stays watched in case it returns."
                    : "Could not load this record right now; kept watched."}
                </p>
                <button
                  type="button"
                  className="btn btn-sm"
                  data-testid={`watch-remove-${id}`}
                  onClick={() => toggleWatch(id)}
                >
                  Unwatch
                </button>
              </article>
            );
          }
          const signals = row.signals;
          const summary = [
            signals.kevListed ? "KEV listed" : "Not KEV listed",
            signals.epssPercent !== null ? `EPSS ${signals.epssPercent}%` : "EPSS unknown",
            signals.cvssScore !== null ? `CVSS ${signals.cvssScore}` : "Unscored",
          ].join(" · ");
          return (
            <article className="result-row" key={id} data-testid={`watch-row-${id}`}>
              <div className="result-rail">
                {signals.kevListed ? <span className="badge badge-kev">KEV</span> : null}
                <span className="result-date">
                  Published <TimeText value={signals.publishedAt} />
                </span>
              </div>
              <div className="result-body">
                <div className="result-title-line">
                  <span className="result-id-row">
                    <span className="mono result-id" data-testid={`watch-row-${id}-id`}>
                      {row.id}
                    </span>
                  </span>
                  <p className="result-title">{row.title}</p>
                </div>
                {signals.excerpt !== null ? (
                  <p className="result-excerpt">{signals.excerpt}</p>
                ) : null}
                <p className="sr-only" data-testid={`watch-row-${id}-signals`}>
                  {summary}
                </p>
                <div className="result-signal-line">
                  <span className="signal-chip">
                    <span className="signal-chip-label">KEV</span>
                    <strong>{signals.kevListed ? "Listed" : "Not listed"}</strong>
                  </span>
                  <span className="signal-chip">
                    <span className="signal-chip-label">EPSS</span>
                    <strong>
                      {signals.epssPercent !== null ? `${signals.epssPercent}%` : "Unavailable"}
                    </strong>
                  </span>
                  <span className="signal-chip">
                    <span className="signal-chip-label">CVSS</span>
                    <strong>
                      {signals.cvssScore !== null ? `${signals.cvssScore}` : "Unscored"}
                      {signals.cvssVersion !== null ? ` v${signals.cvssVersion}` : ""}
                    </strong>
                  </span>
                </div>
                <div className="result-actions">
                  <a className="btn btn-sm" href={row.officialUrl}>
                    Official CVE record
                  </a>
                  <button
                    type="button"
                    className="btn btn-sm"
                    data-testid={`watch-remove-${id}`}
                    onClick={() => toggleWatch(row.id)}
                  >
                    Unwatch
                  </button>
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
