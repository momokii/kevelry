import path from "node:path";

import { PageHeader } from "@/components/shell/PageHeader";
import { GraphView } from "@/components/graph/GraphView";
import { openReadDatabase } from "@/lib/db";
import {
  buildKevGraph,
  GRAPH_DEFAULT_NODE_LIMIT,
  GRAPH_MAX_NODE_LIMIT,
  type GraphCohort,
} from "@/lib/graph";

export const revalidate = 60;

export const metadata = {
  title: "Relation graph — Kevelry",
  description:
    "KEV-listed records linked by shared catalog CWEs, vendor labels, and reference hosts. Bounded, labeled edges only.",
};

type RawParams = Record<string, string | string[] | undefined>;

function firstValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") {
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
  }
  return path.join(process.cwd(), "data");
}

type GraphOutcome =
  | { kind: "unavailable" }
  | { kind: "invalid"; message: string }
  | { kind: "graph"; cohort: GraphCohort };

const CVE_ID_PATTERN = /^CVE-[0-9]{4}-[0-9]{4,}$/;

export default async function GraphPage({ searchParams }: { searchParams?: Promise<RawParams> }) {
  const params: RawParams = (await searchParams) ?? {};
  const focusRaw = firstValue(params.focus);
  const focus =
    focusRaw === undefined || focusRaw.trim() === ""
      ? null
      : CVE_ID_PATTERN.test(focusRaw.trim())
        ? focusRaw.trim()
        : null;
  const focusInvalid = focusRaw !== undefined && focusRaw.trim() !== "" && focus === null;
  const limitRaw = firstValue(params.limit);
  const limit =
    limitRaw === undefined || limitRaw.trim() === "" ? GRAPH_DEFAULT_NODE_LIMIT : Number(limitRaw);

  let outcome: GraphOutcome;
  if (focusInvalid || !Number.isSafeInteger(limit) || limit < 1 || limit > GRAPH_MAX_NODE_LIMIT) {
    outcome = {
      kind: "invalid",
      message:
        "Focus must look like CVE-YYYY-NNNN+ and limit must be an integer between 1 and 300.",
    };
  } else {
    try {
      const db = openReadDatabase(resolveDataDir());
      try {
        outcome = { kind: "graph", cohort: buildKevGraph(db, { focus, nodeLimit: limit }) };
      } catch (error) {
        outcome =
          error instanceof RangeError
            ? { kind: "invalid", message: "Focus is not a KEV-listed PUBLISHED record." }
            : { kind: "unavailable" };
      }
    } catch {
      outcome = { kind: "unavailable" };
    }
  }

  return (
    <main className="page" data-testid="graph-root" id="main-content">
      <PageHeader
        eyebrow={
          <>
            <span>Graph</span>
            <span className="dot" aria-hidden="true" />
            <span>KEV cohort</span>
            <span className="dot" aria-hidden="true" />
            <span>bounded and labeled</span>
          </>
        }
        title="What links these records?"
        lede="KEV-listed records joined by shared catalog CWEs, normalized vendor labels, and reference hostnames. Every edge kind is inspectable; bounds are stated, never silent sampling."
      />
      {outcome.kind === "unavailable" ? (
        <div className="notice" data-testid="graph-unavailable">
          <span>
            <strong>Local snapshot unavailable.</strong> The retained snapshot could not be read. No
            data is shown rather than substituted data.
          </span>
        </div>
      ) : outcome.kind === "invalid" ? (
        <div className="notice" data-testid="graph-invalid">
          <span>{outcome.message}</span>
        </div>
      ) : (
        <GraphView cohort={outcome.cohort} limit={limit} />
      )}
    </main>
  );
}
