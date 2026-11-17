import { apiPreflight, withApiRoute } from "../_lib/api-route";
import { ApiError } from "../_lib/errors";
import { cachedOkResponse } from "../_lib/http-cache";
import { buildProvenance } from "../_lib/provenance";
import { parseCveIdParam } from "../_lib/radar-api";
import {
  buildKevGraph,
  GRAPH_DEFAULT_NODE_LIMIT,
  GRAPH_MAX_NODE_LIMIT,
} from "../../../../src/lib/graph";

export const dynamic = "force-dynamic";

export async function OPTIONS(request: Request): Promise<Response> {
  return apiPreflight(request);
}

/**
 * Bounded KEV-cohort relationship graph. Nodes are KEV-listed PUBLISHED
 * records; edges join shared catalog CWEs, normalized vendor labels, and
 * reference hostnames — labeled kinds only, never inferred relations.
 * `focus` selects an ego neighborhood; without it the cohort is the
 * top-EPSS KEV members up to the node limit. Caps are part of the response,
 * never silent sampling.
 */
export const GET = withApiRoute(async ({ request, db, rate }) => {
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
      groups: cohort.groups,
      hubs: cohort.hubs,
      summaries: cohort.summaries,
      cweDetails: cohort.cweDetails,
      cweCatalog: cohort.cweCatalog,
      coverage: {
        eligibleCohort: cohort.eligibleCohort,
        returned: cohort.focus === null ? cohort.hubs.length : cohort.nodes.length,
        edgeCount: cohort.edges.length,
      },
      truncated: cohort.truncated,
      provenance: buildProvenance(db, nowIso),
    },
    rate,
  );
});
