import path from "node:path";

import { mapReplayReason } from "@/app/api/v1/_lib/shared";
import { openDatabase, type CveDatabase } from "@/lib/db";
import { isCheckpointExpired, launchDay, listCheckpoints, replayCheckpoint } from "@/lib/radar";
import {
  ReplayLists,
  ReplayMasthead,
  ReplayModelChanged,
  ReplayOrdering,
  ReplaySelector,
  ReplayUnavailable,
  type ReplaySelection,
} from "@/components/replay/ReplayView";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Snapshot replay - CVE Change Radar",
  description:
    "Restore a retained daily checkpoint and ranking policy version. Unavailable states never substitute current data.",
};

type ReplayParams = {
  date?: string | string[] | undefined;
  model?: string | string[] | undefined;
};

function firstParam(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
}

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

function readDb<T>(fn: (db: CveDatabase) => T): T | null {
  let handle = null;
  try {
    handle = openDatabase({ dataDir: resolveDataDir() });
  } catch {
    return null;
  }
  try {
    return fn(handle);
  } catch {
    return null;
  } finally {
    handle.close();
  }
}

function bannerFor(selectedDate: string, kind: string, policyVersion: string | null): string {
  if (kind === "available" && policyVersion !== null) {
    return `Historical context: retained snapshot dated ${selectedDate}, ranking policy ${policyVersion}. Current links are labeled current.`;
  }
  if (kind === "expired") {
    return `Historical context: checkpoint ${selectedDate} is expired and unavailable. Current links are labeled current.`;
  }
  if (kind === "model-changed") {
    return `Historical context: retained snapshot dated ${selectedDate} cannot be replayed under the requested model. Current links are labeled current.`;
  }
  if (kind === "store-missing" || kind === "empty") {
    return "Historical context: no retained checkpoint is available. Current links are labeled current.";
  }
  return `Historical context: no snapshot is retained for ${selectedDate}. Current links are labeled current.`;
}

export default async function ReplayPage({
  searchParams,
}: {
  searchParams: Promise<ReplayParams>;
}) {
  const params = await searchParams;
  const requestedDate = firstParam(params.date).slice(0, 32);
  const rawModel = firstParam(params.model).slice(0, 64).trim();
  const expectedModel = rawModel === "" ? undefined : rawModel;
  const asOfDate = new Date().toISOString().slice(0, 10);

  const loaded = readDb((handle) => ({
    checkpoints: listCheckpoints(handle),
    launch: launchDay(handle),
  }));
  if (loaded === null) {
    return (
      <main className="ledger-page" data-testid="replay-root">
        <h1>Snapshot replay</h1>
        <ReplayMasthead bannerText={bannerFor("", "store-missing", null)} />
        <ReplayUnavailable reason="Snapshot unavailable: the retained history store could not be opened on this server." />
      </main>
    );
  }

  const checkpoints = loaded.checkpoints;
  const launch = loaded.launch;
  if (checkpoints.length === 0 || launch === null) {
    return (
      <main className="ledger-page" data-testid="replay-root">
        <h1>Snapshot replay</h1>
        <ReplayMasthead bannerText={bannerFor("", "empty", null)} />
        <ReplayUnavailable reason="no checkpoints retained; missing days are ineligible, never interpolated" />
      </main>
    );
  }

  const newest = checkpoints[checkpoints.length - 1];
  if (newest === undefined) {
    return (
      <main className="ledger-page" data-testid="replay-root">
        <h1>Snapshot replay</h1>
        <ReplayMasthead bannerText={bannerFor("", "empty", null)} />
        <ReplayUnavailable reason="no checkpoints retained; missing days are ineligible, never interpolated" />
      </main>
    );
  }
  const selectedDate = requestedDate === "" ? newest.checkpointDate : requestedDate;
  const knownDates = new Set(checkpoints.map((row) => row.checkpointDate));
  const selection: ReplaySelection = {
    selectedDate,
    expectedModel,
    retainedFrom: checkpoints[0]?.checkpointDate ?? selectedDate,
    retainedTo: newest.checkpointDate,
    launchDay: launch,
    checkpoints: checkpoints.map((row) => ({
      checkpointDate: row.checkpointDate,
      policyVersion: row.policyVersion,
      expired: isCheckpointExpired(row.checkpointDate, asOfDate),
    })),
  };
  const selectorDate = knownDates.has(selectedDate) ? selectedDate : newest.checkpointDate;
  const selector: ReplaySelection = { ...selection, selectedDate: selectorDate };

  const result = readDb((handle) =>
    replayCheckpoint(
      handle,
      selectedDate,
      expectedModel === undefined ? { asOfDate } : { asOfDate, expectedModelVersion: expectedModel },
    ),
  );
  if (result === null) {
    return (
      <main className="ledger-page" data-testid="replay-root">
        <h1>Snapshot replay</h1>
        <ReplayMasthead bannerText={bannerFor("", "store-missing", null)} />
        <ReplayUnavailable reason="Snapshot unavailable: the retained history store could not be read on this server." />
      </main>
    );
  }
  if (result.status === "unavailable") {
    const kind = mapReplayReason(result.reason);
    return (
      <main className="ledger-page" data-testid="replay-root">
        <h1>Snapshot replay</h1>
        <ReplayMasthead bannerText={bannerFor(selectedDate, kind, null)} />
        <ReplaySelector selection={selector} />
        {kind === "model-changed" ? (
          <ReplayModelChanged reason={result.reason} />
        ) : (
          <ReplayUnavailable reason={result.reason} />
        )}
      </main>
    );
  }

  return (
    <main className="ledger-page" data-testid="replay-root">
      <h1>Snapshot replay</h1>
      <ReplayMasthead
        bannerText={bannerFor(selectedDate, "available", result.manifest.policyVersion)}
      />
      <ReplaySelector selection={selector} />
      <ReplayLists manifest={result.manifest} />
      <ReplayOrdering manifest={result.manifest} />
    </main>
  );
}
