"use client";

import { useEffect, useState } from "react";

import { useDisplayPrefs, WATCH_MAX_IDS } from "../ledger/DisplayPrefs";

type WatchRow =
  | { status: "loading" }
  | { status: "ready"; id: string; title: string; detail: string; officialUrl: string }
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
  const kev = data.kev as { listed?: boolean } | undefined;
  const epss = data.epss as { status?: string; value?: number | null } | undefined;
  const cvss = data.cvssPrimary as { status?: string; baseScore?: number | null } | undefined;
  const signals: string[] = [];
  signals.push(kev?.listed === true ? "KEV listed" : "Not KEV listed");
  signals.push(
    epss?.status === "known" && typeof epss.value === "number"
      ? `EPSS ${(epss.value * 100).toFixed(2)}%`
      : "EPSS unknown",
  );
  signals.push(
    cvss?.status === "known" && typeof cvss.baseScore === "number"
      ? `CVSS ${cvss.baseScore}`
      : "Unscored",
  );
  const title = data.title;
  const officialUrl = data.officialUrl;
  return {
    status: "ready",
    id: cveId,
    title: typeof title === "string" && title !== "" ? title : cveId,
    detail: signals.join(" · "),
    officialUrl:
      typeof officialUrl === "string" && officialUrl !== "" ? officialUrl : officialFallback(cveId),
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
          return (
            <article className="ledger-row" key={id} data-testid={`watch-row-${id}`}>
              <span className="ledger-row-id" data-testid={`watch-row-${id}-id`}>
                {row.id}
              </span>
              <p className="ledger-row-title">{row.title}</p>
              <p className="ledger-row-signals" data-testid={`watch-row-${id}-signals`}>
                {row.detail}
              </p>
              <a className="ledger-row-action" href={row.officialUrl}>
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
            </article>
          );
        })}
      </div>
    </section>
  );
}
