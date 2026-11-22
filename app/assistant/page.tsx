// /assistant — the research desk.
//
// The page is a shell around one client component, and it does three things the
// client must not do itself:
//
//  1. **Gates the feature on the server.** `AI_ENABLED`, the gateway key and the
//     daily ledger decide whether a composer exists at all. A disabled instance
//     renders the reason and the variable an operator sets — never a composer
//     that would fail on submit.
//  2. **Builds the suggestions from this corpus.** Three questions, each with the
//     count that made it offerable, read on this request. Nothing is hard-coded
//     and no zero-count suggestion is offered.
//  3. **Pins `/assistant?cve=`.** The record id is shape-validated here, so the
//     client only ever holds an id the route will accept.
//
// The page writes nothing and stores nothing: the transcript is the client's, and
// every turn is a POST that the route answers from the corpus.

import { AssistantDesk } from "@/components/assistant/AssistantDesk";
import { ASSISTANT_CVE_CONTEXT_PATTERN } from "@/app/api/assistant/_lib/body";
import { AI_MODEL_DEFAULT, aiGate, loadAiConfig, type AiDisabledReason } from "@/lib/ai/config";
import { readSuggestionCounts, buildAssistantSuggestions } from "@/lib/ai/suggestions";
import { createAiUsageLedger } from "@/lib/ai/usage";
import { buildProvenance } from "@/lib/provenance";
import { openReadDatabase, type CveDatabase } from "@/lib/db";
import path from "node:path";

export const metadata = {
  title: "Ask the corpus — Kevelry",
  description:
    "A research desk over this instance's own CVE records. Every number is linked to the record it came from, and the tool calls are shown.",
};

/** Suggestions are read on the request that renders them, never baked at build. */
export const dynamic = "force-dynamic";

const AS_OF_FORMAT = new Intl.DateTimeFormat("en-GB", {
  day: "numeric",
  month: "short",
  year: "numeric",
  timeZone: "UTC",
});

function resolveDataDir(): string {
  const raw = process.env.DATA_DIR;
  if (raw !== undefined && raw.trim() !== "") return raw;
  return path.join(process.cwd(), "data");
}

function formatAsOf(iso: string | null): string | null {
  if (iso === null) return null;
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return `${AS_OF_FORMAT.format(new Date(ms))} · UTC`;
}

interface DeskFacts {
  /** Null when the desk may take questions. */
  reason: AiDisabledReason | null;
  suggestions: ReturnType<typeof buildAssistantSuggestions>;
  asOf: string | null;
  /** `AI_MODEL`, printed in a downloaded brief. */
  modelId: string;
}

/**
 * Everything the server decides before the desk renders: the gate, the three
 * suggestions with their counts, and the corpus instant.
 *
 * A database that cannot be opened does not close the gate: an unreadable corpus
 * is not proof that the budget is spent, and the route reports `INTERNAL` for a
 * turn that really cannot be answered. It does mean there is nothing to suggest.
 */
function readDeskFacts(): DeskFacts {
  let config: ReturnType<typeof loadAiConfig>;
  try {
    config = loadAiConfig(process.env);
  } catch {
    return { reason: "invalid-config", suggestions: [], asOf: null, modelId: AI_MODEL_DEFAULT };
  }

  let db: CveDatabase | null = null;
  try {
    db = openReadDatabase(resolveDataDir());
  } catch {
    db = null;
  }

  let gate = aiGate(config);
  if (db !== null && gate.enabled) {
    try {
      const ledger = createAiUsageLedger({
        db,
        budget: {
          sessionBudgetTokens: config.sessionBudgetTokens,
          dailyBudgetUsd: config.dailyBudgetUsd,
        },
      });
      gate = aiGate(config, { dailyBudgetExceeded: () => ledger.dailyBudgetExceeded() });
    } catch {
      // An unreadable spend ledger is not proof of headroom or of exhaustion;
      // the route's own budget probe stays the authority for a turn.
      gate = aiGate(config);
    }
  }

  if (!gate.enabled) {
    return { reason: gate.disabled ?? "off", suggestions: [], asOf: null, modelId: config.model };
  }
  if (db === null) {
    return { reason: null, suggestions: [], asOf: null, modelId: config.model };
  }
  return {
    reason: null,
    suggestions: buildAssistantSuggestions(readSuggestionCounts(db)),
    asOf: formatAsOf(buildProvenance(db, new Date().toISOString()).sources.cve.lastAcceptedAt),
    modelId: config.model,
  };
}

export default async function AssistantPage({
  searchParams,
}: {
  searchParams: Promise<{ cve?: string }>;
}) {
  const params = await searchParams;
  const rawCve = Array.isArray(params.cve) ? params.cve[0] : params.cve;
  const cveContext =
    typeof rawCve === "string" && ASSISTANT_CVE_CONTEXT_PATTERN.test(rawCve.toUpperCase())
      ? rawCve.toUpperCase()
      : null;

  const facts = readDeskFacts();
  const gate =
    facts.reason === null
      ? { enabled: true as const }
      : { enabled: false as const, reason: facts.reason };

  return (
    <main className="page assistant-page" id="main-content" data-testid="assistant-root">
      <header className="assistant-head">
        <div className="assistant-head-main">
          <h1>Ask the corpus</h1>
          <p className="page-lede">
            Answers come from the records this instance holds. Every number is linked to the record
            it came from, and each tool call the server ran is listed beside the answer.
          </p>
        </div>
        {facts.asOf !== null ? (
          <p className="assistant-asof" data-testid="assistant-asof">
            corpus as of {facts.asOf}
          </p>
        ) : null}
      </header>

      <AssistantDesk
        gate={gate}
        suggestions={facts.suggestions}
        initialCveContext={cveContext}
        modelId={facts.modelId}
      />
    </main>
  );
}
