import { getDb } from "../_lib/shared";
import {
  acquireConcurrencySlot,
  ApiError,
  assertRequestBounds,
  buildProvenance,
  cachedOkResponse,
  errorResponse,
  parseCveIdParam,
  preflightResponse,
  releaseConcurrencySlot,
  reserveRateLimit,
} from "../_lib/shared";
import {
  buildKevGraph,
  GRAPH_DEFAULT_NODE_LIMIT,
  GRAPH_MAX_NODE_LIMIT,
} from "../../../../src/lib/graph";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return preflightResponse(request);
}

/**
 * Bounded KEV-cohort relationship graph. Nodes are KEV-listed PUBLISHED
 * records; edges join shared catalog CWEs, normalized vendor labels, and
 * reference hostnames — labeled kinds only, never inferred relations.
 * `focus` selects an ego neighborhood; without it the cohort is the
 * top-EPSS KEV members up to the node limit. Caps are part of the response,
 * never silent sampling.
 */
export async function GET(request: Request): Promise<Response> {
  let db = null;
  try {
    db = getDb();
  } catch {
    return errorResponse(request, "INTERNAL", "Unexpected failure handling the request.", null);
  }
  const rate = reserveRateLimit(request, db);
  if (rate instanceof Response) return rate;
  if (!acquireConcurrencySlot()) {
    return errorResponse(
      request,
      "RATE_LIMITED",
      "Server is busy. Retry after 60 seconds.",
      db,
      undefined,
      rate,
    );
  }
  try {
    assertRequestBounds(request);
    const params = new URL(request.url).searchParams;
    const focus = parseCveIdParam(params.get("focus"));
    // Graph pages are SVG nodes, not record rows: own 1-300 bound instead
    // of the shared 1-200 page cap.
    const rawLimit = params.get("limit");
    let nodeLimit = GRAPH_DEFAULT_NODE_LIMIT;
    if (rawLimit !== null && rawLimit !== "") {
      if (!/^[0-9]+$/.test(rawLimit)) {
        throw new ApiError(
          "BAD_LIMIT",
          400,
          `limit must be an integer between 1 and ${GRAPH_MAX_NODE_LIMIT}.`,
        );
      }
      const parsed = Number(rawLimit);
      if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > GRAPH_MAX_NODE_LIMIT) {
        throw new ApiError(
          "BAD_LIMIT",
          400,
          `limit must be an integer between 1 and ${GRAPH_MAX_NODE_LIMIT}.`,
        );
      }
      nodeLimit = parsed;
    }
    const nowIso = new Date().toISOString();
    let cohort;
    try {
      cohort = buildKevGraph(db, { focus, nodeLimit });
    } catch (error) {
      if (error instanceof RangeError) {
        throw new ApiError("CVE_NOT_FOUND", 404, `Focus is not a KEV-listed PUBLISHED record.`);
      }
      throw error instanceof Error ? error : new Error(String(error));
    }
    return cachedOkResponse(
      request,
      db,
      {
        focus: cohort.focus,
        nodes: cohort.nodes,
        edges: cohort.edges,
        coverage: {
          eligibleCohort: cohort.eligibleCohort,
          returned: cohort.nodes.length,
          edgeCount: cohort.edges.length,
        },
        truncated: cohort.truncated,
        provenance: buildProvenance(db, nowIso),
      },
      rate,
    );
  } catch (error) {
    if (error instanceof ApiError) {
      return errorResponse(request, error.code, error.message, db, error.details, rate);
    }
    return errorResponse(
      request,
      "INTERNAL",
      "Unexpected failure handling the request.",
      db,
      undefined,
      rate,
    );
  } finally {
    releaseConcurrencySlot();
  }
}
